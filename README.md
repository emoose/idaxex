# idaxex

idaxex is a native loader plugin for IDA Pro, adding support for loading in Xbox360 XEX & Xbox XBE executables.

Originally started as an [IDAPython loader](https://github.com/emoose/reversing/blob/master/xbox360.py), work was continued as a native DLL to solve the shortcomings of it.

This should have the same features as xorloser's great Xex Loader (for IDA 6 and older), along with additional support for some early non-XEX2 formats, such as XEX1 used on beta-kits.

XBE files are additionally supported, adding a few extra features over the loader included with IDA.

## Supported formats

Includes support for the following Xbox executables:
- XEX2 (>= kernel 1861)
- XEX1 (>= 1838)
- XEX% (>= 1746)
- XEX- (>= 1640)
- XEX? (>= 1529)
- XEX0 (>= 1332)
- XBE (>= XboxOG ~3729)

## Features

- Can handle compressed/uncompressed images, and encrypted/decrypted (with support for retail, devkit & pre-release encryption keys)
- Reads in imports & exports into the appropriate IDA import/export views.
- Automatically names imports that are well-known, such as imports from the kernel & XAM, just like xorloser's loader would.
- PE sections are created & marked with the appropriate permissions as given by the PE headers.
- AES-NI support to help improve load times of larger XEXs.
- Marks functions from .pdata exception directory & allows IDA's eh_parse plugin to read exception information.
- Passes codeview information over to IDA, allowing it to prompt for & load PDBs without warnings/errors.
- XBE: adds kernel imports to IDA imports view
- XBE: parses XTLID section if exists and names most Xbox SDK library functions used by the executable

## Install
Builds for IDA 9 are available in the releases section.

To install the loader just extract the contents of the folder for your IDA version into IDA's install folder (eg. C:\Program Files\IDA Professional 9.0\)

I recommend pairing this loader with the PPCAltivec plugin, an updated version for IDA 7 is available at hayleyxyz's repo here: https://github.com/hayleyxyz/PPC-Altivec-IDA

## Building

Make sure to clone repo recursively for excrypt submodule to get pulled in.

**Windows**

Clone the repo into your idasdk\ldr\ folder and then build idaxex.sln with VS2022.

**Linux**

- Setup [ida-cmake](https://github.com/allthingsida/ida-cmake) in your idasdk folder
- Make sure IDASDK env var points to your idasdk folder
- Clone idaxex repo
- Run `cmake . -DEA64=YES` inside idaxex folder
- Run `make`
- To build xex1tool run cmake/make inside the xex1tool folder

On newest IDA you may need to edit ida-cmake common.cmake and change `libida64.so` to `libida.so` for build to link properly.

## Credits
Based on work by the Xenia project, XEX2.bt by Anthony, xextool 0.1 by xor37h, Xex Loader & x360_imports.idc by xorloser, xkelib, and probably many others I forgot to name.

Thanks to everyone involved in the Xbox 360 modding/reverse-engineering community!

XTLID parsing supported thanks to the [XboxDev/xtlid project](https://github.com/XboxDev/xtlid).

# xex1tool
Also included is an attempt at recreating xorloser's XexTool, for working with older pre-XEX2 executables.  
(The name is only to differentiate it from the original XexTool - it'll still support XEX2 files fine)

So far it can print info about the various XEX headers via `-l`, and extract the basefile (PE/XUIZ) from inside the XEX.

For XEX files that are both decrypted & decompressed xex1tool can also convert a VA address to a file offset for you, making file patching a little easier.

Support for other XexTool features may slowly be added over time (of course any help is appreciated!)
