# How to load your unsigned driver and hide all traces after that

About TESTSIGNING mode: https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option


1) Run cmd.exe with administrator rights and enter: bcdedit.exe /set TESTSIGNING ON
2) Reboot your PC
3) In user-mode app load CI.dll with LoadLibraryEx and get kernel address of g_CiOptions flag
4) Create shared memory buffer with information for kernel driver
5) Load the driver to kernel with service or ZwLoadDriver
6) Driver patch g_CiOptions to off TESTSIGNING mode
7) In your user-mode app, run bcdedit.exe /set TESTSIGNING OFF
8) Clear traces in registry
