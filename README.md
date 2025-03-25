<p align="center">A Basic Memory Utility DLL for external, internal, and kernel level execution</p>

---
# Usage
### External and Internal Usage
Functions for internal and external usage are defined in the Memory namespace, with functions specifically made for external usage end in Ex
A dll can be very simply injected with the Memory::simpleInject() function<br>

*Note: if your injected dll depends on asgard, a way to make it work is to inject asgard into the target application, then inject your own dll.*

### Driver Usage

The loadDriver function of the KernelMemory attempts to run an instance of kdmapper in the same directory,<br>
to correctly use this capability, place the "AsgardDriver.sys", "kdmapper.exe", and the executable calling loadDriver all in the same directory.<br>
After the driver is mapped into memory, you can then call the KernelMemory functions to interact with it.<br>

*Note: Any Error caused in the kernel will result in a full computer crash<br>The Driver is not very well tested on a wide variety of OS. The Driver has been tested and confirmed to work on a Microsoft Windows 11 development environment, Version 2310: https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/*

Note:
- Dont make the same mistake I did, make sure to manage x32/x64 configurations on each of the builds depending on what your targeting.

# Linking your project to Asgard in Visual Studio:
- Project Configuration -> General -> C++ Language Standard -> ISO C++20 Standard (/std:c++20)
- Project Configuration -> Advanced -> Character Set -> Not Set
- Project Configuration -> Linker -> Input -> Additional Dependencies -> Asgard.lib;
- Project Configuration -> Linker -> General -> Additional Library Directories -> (path to Asgard.lib)
- Project Configuration -> C++ -> General -> Additional Include Directories -> (path to the Asgard header Files)

