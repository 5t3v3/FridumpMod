# Fridump
Fridump (v0.1) is an open source memory dumping tool, primarily aimed to penetration testers and developers. Fridump is using the Frida framework to dump accessible memory addresses from any platform supported. It can be used from a Windows, Linux or Mac OS X system to dump the memory of an iOS, Android or Windows application.

**This is a modified version of fridump for better debugging purposes.**

Usage
---
![image](https://github.com/user-attachments/assets/f9a660ad-3b57-4a2e-b413-f0240a28fba1)

![image](https://github.com/user-attachments/assets/e3e4b3c1-d7da-487d-ba02-72ab89cc64c7)

![image](https://github.com/user-attachments/assets/a36add4e-0335-43f6-9dd6-b8ca0a4e2fc8)

How to:

      fridump [-h] [-o dir] [-v] [-r] [-s] [--max-size bytes]

The following are the main flags that can be used with fridump:

      optional arguments:
      -h, --help         show this help message and exit
      -o dir, --out dir  provide full output directory path. (def: 'dump')
      -v, --verbose      verbose
      -r, --read-only    dump read-only parts of memory. More data, more errors
      -s, --strings      run strings on all dump files. Saved in output dir.
      -l, --listprocess  List all running processes
      --max-size bytes   maximum size of dump file in bytes (def: 20971520)

Examples:

      fridump                    -  List the processes and Dump the memory
      fridump -s                 -  List the processes Dump the memory of an Android/iOS device and run strings on all dump files
      fridump -r -o [full_path]  -  Dump the memory of a local application and save it to the specified directory

Installation
---
To install Fridump you just need to clone it from git and run it:

      https://github.com/5t3v3/FridumpMod/
      
      python fridump-dbg.py -h
            
Pre-requisites
---
To use fridump you need to have frida installed on your python environment and frida-server on the device you are trying to dump the memory from.
The easiest way to install frida on your python is using pip:

    pip install frida
    
More information on how to install Frida can be found [here](http://www.frida.re/docs/installation/)

For iOS, installation instructions can be found [here](http://www.frida.re/docs/ios/).

For Android, installation instructions can be found [here](http://www.frida.re/docs/android/).

Note: On Android devices, make sure that the frida-server binary is running as root!

Disclaimer
---
* This is a debug version I built for myself, so I expect some bugs to be present
* I am not a developer, so my coding skills might not be the best

This tool has been tested on a Windows 7 and a Mac OS X laptop, dumping the memory of:  
* an android emulator ( Genymotion )
* Using a Kali VM in Windows 10 Host
 
Therefore, if this tool is not working for you, I apologise and I will try to fix it.

Any suggestions and comments are welcome!
