# HiveOpLock

this driver is a direct response to the LegacyHive Exploit to deny it from gaining any oplocks to the HKCU hive (NTUSER.dat usrclass.dat)

Note that you need fltmgr.lib to build the driver other wise it wont build

**2026/07/18**: Fixed a minor issue in the name constants. String patterns for `FsRtlIsNameInExpression` must be strictly capitalized to handle mixed-case inputs correctly. Sorry for any inconvenience.
