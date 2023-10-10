# QuickFileVerifier

Run `./QuickFileVerifier.ps1 -help` for more information.

## Warning!

Make sure that you read the TERMS_AND_CONDITIONS.md file before you use this program. Using this program means that you accept the terms.

**Never** run any _.ps1_ or _.reg_ files without checking the files yourselves to avoid damaging your computer.

GPG needs to run in English for the check message to be printed out correctly. You will still see the GPG output.

## Description

Enables for you to quickly check for the GPG signature status, Code Signing signature status, SHA1; SHA256; SHA512 and MD5 hashes of a file.

## Usage

### From the context menu

Just right click the file and select "Verify File with QFV" from the context menu. You will have to add required keys into `regedit.exe` to get the context menu entry.

You can quickly add the keys with the provided `QFV - AddToContextMenu.reg` file. Make sure that you edit the file path of `QuickFileVerifier.ps1`.

### From the terminal

Run the file as: `.\QuickFileVerifier.ps1`

Example:
```powershell
.\QuickFileVerifier.ps1 .\README.md
```

Warning: You may need to set your `ExecutionPolicy` to `RemoteSigned` with this command to run a script. Windows does not allow users to run scripts out of the box.
You can set it by pasting this command:
```powershell
Set-ExecutionPolicy RemoteSigned
```
To run this program everywhere, you will need to add it to the PATH.

You can run this command to add the directory of the script into the PATH. Edit the required part with your path.
```powershell
set PATH=%PATH%;<YOUR PATH HERE>
```

## Issues

Just open one here and I will check it out.

## Notes

While editing the .reg file to add the program into the context menu, the backslashes in the path should be written twice as such: `\\`. For example, `C:\Users\user\Desktop\QuickFileVerifier.ps1` should be written as `C:\\Users\\user\\Desktop\\QuickFileVerifier.ps1`.

