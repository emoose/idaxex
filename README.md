# idaxex
idaxex is an Xbox360 XEX loader plugin for IDA Pro 7+, based on my earlier [xbox360.py loader](https://github.com/emoose/reversing/blob/master/xbox360.py).

Hopefully the move to a native loader DLL should help solve all the shortcomings the python loader had.

## Status
Most of the functionality from the python loader has been ported over, though hasn't been tested out much yet.

Only XEX2 is supported right now, hopefully can add support for XEX1 etc once XEX2 is working fine.

Both uncompressed & compressed XEXs should now be supported, thanks to LZX code from cabextract 0.2. 

Encryption support hasn't been added yet, will copy over from python loader soon.

Imports seem to get read in & labelled fine, haven't looked into adding to imports window yet though, but looks like it should be possible.

Exports labelling code has been ported but not tested yet.

## Building
You'll need to copy this repo into your idasdk/ldr/ folder, eg. for me I have it at C:\idasdk\ldr\xex\idaxex.sln

With that done you should be able to just build the solution, ida32 will build a DLL for 32-bit IDA while ida64 will build for 64-bit.

## Thanks
This loader wouldn't be possible without the research & info provided by others.

In part, this loader is based on work by the Xenia project, XEX2.bt by Anthony, xextool 0.1 by xor37h, x360_imports.idc by xorloser, xkelib...

## License
All code is licensed under GPLv3 unless otherwise stated.
