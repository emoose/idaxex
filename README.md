# idaxex

idaxex is a native loader plugin for IDA Pro, adding support for loading in Xbox360 XEX executables.

Originally started as an [IDAPython loader](https://github.com/emoose/reversing/blob/master/xbox360.py), work was continued as a native DLL to solve the shortcomings of it.

This should hopefully have the same features as xorloser's great Xex Loader (for IDA 6 and older), along with additional support for some early non-XEX2 formats, such as XEX1 used on beta-kits.

## Supported formats

Includes support for the following XEX formats:
- XEX2 (>= kernel 1861)
- XEX1 (>= 1838)
- XEX% (>= 1746)
- XEX- (>= 1640)
- XEX? (>= 1529)
- XEX0 (>= 1332)

## Features

- Can handle compressed/uncompressed images, and encrypted/decrypted (with support for retail, devkit & pre-release encryption keys)
- Reads in imported functions & libraries into IDA's "imports" window, and also reads exports from the loaded module into the "exports" window.
- Automatically names imports that are well-known, such as imports from the kernel & XAM, just like xorloser's loader would.
- PE sections are created & marked with the appropriate permissions as given by the PE headers.
- Hardware-accelerated AES-NI support which should allow loading encrypted XEXs pretty quickly!

## Install
Builds for IDA 7.2-7.5, both 32-bit and 64-bit, are available in the releases section.

To install the loader simply extract the release zip into your IDA\loaders\ directory, eg. "C:\Program Files\IDA 7.0\loaders\idaxex64.dll"

I recommend pairing this loader with the PPCAltivec plugin, an updated version for IDA 7 is available at yui-konnu's repo here: https://github.com/yui-konnu/PPC-Altivec-IDA

## Building
You'll need to copy this repo into your idasdk\ldr\ folder, eg. for me I have it at C:\idasdk\ldr\xex\idaxex.sln

With that done you should be able to just build the solution, ida32 will build a DLL for 32-bit IDA while ida64 will build for 64-bit.

This project is designed for IDA on Windows but maybe it could work on other OS's too, I've tried to make sure not to include any Windows-specific things, so hopefully there's a good chance for it to work. If you try it out please let me know how it goes!

## Todo

I've been using this loader for a few months now and it's worked pretty well, but no doubt there's probably bugs to be found in it - if you encounter anything strange please don't hesitate to make a bug report on the issue tracker!

- .pdata support will be added soon, wasn't aware this section could be used for storing exports, but zeroKilo's [XEXLoaderWV for Ghidra](https://github.com/zeroKilo/XEXLoaderWV) gives a great look at how this section should be handled - will add support for loading in this section soon.

- Right now known-import-names are hardcoded inside the loader, it'd be nice if we can make them external somehow... xorloser's loader seems to call into a DoNameGen function inside x360_imports.idc for this - maybe we can do the same?

## Credits
idaxex is based on work by the Xenia project, XEX2.bt by Anthony, xextool 0.1 by xor37h, Xex Loader & x360_imports.idc by xorloser, xkelib, and probably many others I forgot to name!

Thanks to everyone involved in the Xbox 360 modding/reverse-engineering community!

# xex1tool
Also included is an attempt at recreating xorloser's XexTool, with additions from idaxex such as support for XEX1 and older.  
(The name is only to differentiate it from the original XexTool - it'll still support XEX2 files fine)

So far it can print info on the various XEX headers (via -l), and extract the basefile (PE/XUIZ) from inside the XEX.

Support for other XexTool features will slowly be added over time (of course any help is appreciated!)
