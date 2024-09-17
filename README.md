# VoxelMapRedir

`main.cpp` is the code for a simple injector tool that will wait for a running `javaw.exe` process, and then inject `VoxelMapRedirDLL.dll` into it.

`dllmain.cpp` is the code for an injected DLL that fixes an old version of the Minecraft mod *VoxelMap*. It allows the mod to work when connecting to realms. It hooks `CreateFileW` and `GetFileAttributesExW` looking for filenames with specific path elements, and will rewrite them to utilize a file containing the string "realms" in place of an IP address, which the realm system does not expose.  
It requires linking in a multi-threaded version of libMinHook and requires the associated MinHook.h file.


