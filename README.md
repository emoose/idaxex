# idaxex
idaxex is an Xbox360 XEX loader plugin for IDA Pro 7+, based on my earlier [xbox360.py loader](https://github.com/emoose/reversing/blob/master/xbox360.py).

Hopefully the move to a native loader DLL should help solve the shortcomings the python loader had.

## Status
The loader should currently support:
- compressed/encrypted XEXs (with 4 different encryption keys supported: retail/devkit pairs for both final & pre-release XEXs)
- loading PE segments & XEX sections (aka XEX resources)
- loading module exports/imports (and populating the exports/imports IDA windows too!)
- loading different XEX formats via the same code path (XEX2/XEX1/XEX%/XEX-/XEX?...)
- printing useful information from the XEX headers

There's still a few small things that can be worked on though, but right now I think it should hopefully be on-par with xorloser's excellent Xex Loader.

## Install
To install the loader simply extract the release zip into your IDA/loader/ directory, eg. "C:\Program Files\IDA 7.0\loaders\idaxex64.dll"

I recommend pairing this loader with the PPCAltivec plugin, an updated version for IDA 7 is available at yui-konnu's repo here: https://github.com/yui-konnu/PPC-Altivec-IDA

## Building
You'll need to copy this repo into your idasdk/ldr/ folder, eg. for me I have it at C:\idasdk\ldr\xex\idaxex.sln

With that done you should be able to just build the solution, ida32 will build a DLL for 32-bit IDA while ida64 will build for 64-bit.

This project is designed for IDA on Windows but maybe it could work on other OS's too, I've made sure not to include any Windows-specific things, so hopefully there's a good chance for it to work.
If you try it out please let me know how it goes!

## Contributing

I'd gladly accept any help from people willing to give their time to help improve the loader, 

## Thanks
This loader wouldn't be possible without the research & info provided by others.

In part, this loader is based on work by the Xenia project, XEX2.bt by Anthony, xextool 0.1 by xor37h, xkelib...

Of course thanks goes to xorloser for releasing his Xex Loader for IDA 6 & x360_imports.idc too!

## License
All code is licensed under GPLv3 unless otherwise stated.
