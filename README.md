![logo](https://github.com/TheSph1nx/AbsoluteZero/blob/master/screenshots/AbsoluteZero.png)

# AbsoluteZero
Python APT Backdoor-Botnet / Python MuddyWater Recreation

This project is a Python APT backdoor, optimized for Red Team Post Exploitation Tool, it can generate binary payload or pure python source. The final stub uses polymorphic encryption to give a first obfuscation layer to itself.
Deployment

AbsoluteZero is a complete software written in Python 2.7 and works both on Windows and Linux platforms, in order to make it working you need to have Python 2.7 installed and then using ‘pip’ install the requirements.txt file. Remember that to compile binaries for Windows you have to run the entire software on a Microsoft platform seen that pyinstaller doesn’t allow cross-platform compiling without using vine.

Make sure that Python installation folder is set on ‘C:/Python27‘ to avoid binary compiling troubles.
Version 1.0.0.1

    Fixed some issues on the payload generator.
    Added folder movement from implant cli.
    Added implant persistence.
    Added packet length show option.
    Added notify connection option.
    Added autostart TCP Handler option.
    Added/Fixed screenshot issue (Python wx not found by pyinstaller).
    The implant now can recover the lost connection if the server goes down.
    Implant .exe Tested on Winows7 x64.
    Added configuration file to save the system configuration (xml).
    Added webshell password protected and webshell handler for php reverse shell.
    Fixed bugs on modules : ps, shell.
    Fixed minor bugs.

