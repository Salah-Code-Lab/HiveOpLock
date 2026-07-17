// HiveGuard.c
#include <ntifs.h>
#include <fltKernel.h>
#include <ntdddisk.h>
#include <ntstrsafe.h>


PFLT_FILTER gFilterHandle = NULL;
BOOLEAN gProtectionActive = FALSE;

// Protected filenames (Sufix matching logic)
// Check if filename matches protected hives via a reliable suffix validation
UNICODE_STRING gUsersPattern = RTL_CONSTANT_STRING(L"*\\Users\\*");
UNICODE_STRING gNtUserTail = RTL_CONSTANT_STRING(L"\\ntuser.dat");
UNICODE_STRING gUsrClassTail = RTL_CONSTANT_STRING(L"\\usrclass.dat");

// Oplock FSCTLs

// Only define if they aren't already included by the WDK headers
#ifndef FSCTL_REQUEST_OPLOCK
#define FSCTL_REQUEST_OPLOCK           CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 116, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef FSCTL_REQUEST_FILTER_OPLOCK
#define FSCTL_REQUEST_FILTER_OPLOCK    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 3,   METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef FSCTL_REQUEST_BATCH_OPLOCK
#define FSCTL_REQUEST_BATCH_OPLOCK     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 2,   METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef FSCTL_REQUEST_OPLOCK_LEVEL_2
#define FSCTL_REQUEST_OPLOCK_LEVEL_2   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 1,   METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef FSCTL_REQUEST_OPLOCK_LEVEL_1
#define FSCTL_REQUEST_OPLOCK_LEVEL_1   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0,   METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

extern PULONG InitSafeBootMode;



BOOLEAN IsProtectedHiveFile(PUNICODE_STRING FileName)
{
    // 1. Safety check
    if (!FileName || FileName->Length == 0 || FileName->Buffer == NULL) {
        return FALSE;
    }

    // 2. path check: Is it actually a target hive file type?
    BOOLEAN isHive = FALSE;
    if (RtlSuffixUnicodeString(&gNtUserTail, FileName, TRUE) ||
        RtlSuffixUnicodeString(&gUsrClassTail, FileName, TRUE)) {
        isHive = TRUE;
    }

    if (!isHive) {
        return FALSE;
    }

    // 3. pattern match: Does it live inside a nested \Users\ path?
    if (FsRtlIsNameInExpression(&gUsersPattern, FileName, TRUE, NULL)) {
        return TRUE;
    }

    return FALSE;
}
// Instance setup
NTSTATUS InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
) {
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

// PreFileSystemControl: Detects and stops oplock exploitation paths instantly
FLT_PREOP_CALLBACK_STATUS PreFileSystemControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!gProtectionActive) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 1. Defend against execution paths occurring in system context
    if (PsIsSystemThread(PsGetCurrentThread())) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 2. Extract and sanitize the FSCTL code from the correct structure variant
    ULONG fsctlCode = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;

    if (fsctlCode != FSCTL_REQUEST_OPLOCK_LEVEL_1 &&
        fsctlCode != FSCTL_REQUEST_OPLOCK_LEVEL_2 &&
        fsctlCode != FSCTL_REQUEST_BATCH_OPLOCK &&
        fsctlCode != FSCTL_REQUEST_FILTER_OPLOCK &&
        fsctlCode != FSCTL_REQUEST_OPLOCK) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 3. Evaluate the target file name
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 4. Deny the lock if it Targets User Profile Hives
    if (IsProtectedHiveFile(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS InstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

// Register strictly what we need.
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_FILE_SYSTEM_CONTROL, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreFileSystemControl, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    NULL,
    InstanceSetup,
    InstanceQueryTeardown,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    gProtectionActive = FALSE;
    if (gFilterHandle) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    if (InitSafeBootMode != NULL && *InitSafeBootMode != 0) {
        DriverObject->DriverUnload = DriverUnload;
        return STATUS_SUCCESS;
    }


    NTSTATUS status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    gProtectionActive = TRUE;
    DriverObject->DriverUnload = NULL;
    return STATUS_SUCCESS;
}