# QuickFileVerifier

Current version: 1.0

## Warning!

Make sure that you read the LICENCE.md file before you use this program. Using this program means that you accept the licence.
**Never** run any _.ps1_ or _.reg_ files without checking the files yourselves to avoid damaging your computer.

## Description

Enables for you to quickly check for the GPG signature status, Code Signing signature status, SHA1; SHA256; SHA512 and MD5 hashes of a file.

## Usage

Just right click the file and select "Verify File with QFV" from the context menu. You will have to add required keys into `regedit.exe` to get the context menu entry.

You can quickly add the keys with the provided `QFV - AddToContextMenu.reg` file. Make sure that you edit the file path of `QuickFileVerifier.ps1`.

## Issues

Just open one here and I will check it out.

## Notes

While editing the .reg file to add the program into the context menu, the backslashes in the path should be written twice as such: `\\`. For example, `C:\Users\user\Desktop\QuickFileVerifier.ps1` should be written as `C:\\Users\\user\\Desktop\\QuickFileVerifier.ps1`.

