# windup

Windup is an installer for WinDbg that uses the appinstaller file at https://aka.ms/windbg/download to install the latest version of WinDbg. It also checks for updates each time it is run and will download a new version when it is available in the background.

This is NOT a good replacement for using the appinstaller directly, but is useful on platforms where appinstaller is not available, such as Windows Server.

**This program is not endorsed or supported by Microsoft**

## How to use

Download windup.exe from the latest release. Move this file to wherever you want to install WinDbg. Run windup.exe. It will download the latest version of WinDbg for the current architecture. Instead of running windbg.exe, just use windup.exe and the parameters will automatically be passed on to the latest version of WinDbg that has been downloaded.

## Notes

Old versions of WinDbg are not deleted when a new version is installed. The current version is determined by the "version.txt" file in the same directory.

The signature of the msix file is checked for validity, but it is not checked to be specifically from Microsoft.

The windup process will stay active for as long as the child DbgX.Shell.exe process is running. This is to be compatible with tools that monitor the lifetime of windbg.

File associations are not configured for *.dmp, *.run, etc.

## Contribution

Contributions are welcome. Feel free to file issues or open pull requests.
