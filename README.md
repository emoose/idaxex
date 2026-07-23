# idaxex

idaxex is a native loader plugin for IDA Pro 9.4, adding support for loading Xbox 360 XEX and Xbox XBE executables.

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
- Patched bytes can be written back to input file via IDA `Apply patches to input` option (works for all XBEs, XEX must be both uncompressed & decrypted using `xextool -eu -cu input.xex` first)
- XBE: adds kernel imports to IDA imports view
- XBE: tries naming SDK library functions using [XbSymbolDatabase](https://github.com/Cxbx-Reloaded/XbSymbolDatabase) & data from XTLID section

## Install

Prebuilt releases are available for supported IDA Pro 9.x versions.

IDA Professional is required for Xbox 360 XEX analysis because IDA Free does
not include the PowerPC processor module.

The recommended Windows installation uses an IDA user directory so IDA's
installation files remain unchanged:

1. Create a directory for idaxex, for example
   `%APPDATA%\Hex-Rays\IDA Pro\idaxex`.
2. Copy `loaders\idaxex.dll`, `til\x360.til`, and `til\xkelib.til` from the
   release package into the same relative directories there.
3. Add that directory to the `IDAUSR` environment variable. If `IDAUSR`
   already contains other directories, append the new directory using a
   semicolon on Windows.
4. Restart IDA.

Installing the package's `loaders` and `til` directories directly into the
matching IDA installation is also supported, but normally requires
administrator access.

For PPC Altivec analysis, the PPCAltivec plugin remains a useful companion: https://github.com/hayleyxyz/PPC-Altivec-IDA

## Loading an executable

1. Start IDA Professional 9.4 and choose **New** or **File > Open**.
2. Select the XEX or XBE executable. Change the file filter to **All files**
   if the executable is not displayed.
3. In the load dialog, verify the detected file type:
   - Xbox 360 files should show an `Xbox360 XEX...` format provided by
     `idaxex.dll` and a PowerPC processor.
   - Original Xbox files should show `Xbox XBE file` and the `metapc`
     processor.
4. Accept the load settings. The memory-mapping information dialog shown for
   PowerPC files is expected.
5. If IDA offers to locate a PDB, select a matching PDB when one is available;
   otherwise decline the prompt. A missing PDB does not prevent the executable
   from loading.
6. Confirm successful operation in IDA's Output window. It should report that
   the file was successfully loaded and should identify `idaxex.dll` as the
   selected loader.

For automated compatibility testing, `scripts\Test-IdaLoader.ps1` runs IDA
non-interactively, verifies the detected file type and processor, checks the
created segments, entry points, functions, imports, and names, and creates a
test database:

```powershell
scripts\Test-IdaLoader.ps1 `
  -IdaExe "C:\Program Files\IDA Professional 9.4\ida.exe" `
  -InputFile "C:\samples\default.xex"
```

`scripts\Test-IdaCorpus.ps1` applies the same structural checks to a
SHA-256-deduplicated corpus and writes its inventory, exclusions, per-file
results, and IDA logs below the specified output directory:

```powershell
scripts\Test-IdaCorpus.ps1 `
  -IdaExe "C:\Program Files\IDA Professional 9.4\idat.exe" `
  -InputRoot "C:\samples\xex;D:\additional-samples" `
  -OutputRoot "C:\idaxex-validation" `
  -Magic "XEX0;XEX1;XEX2;XEX-;XEX?;XEX%;XBEH" `
  -MaximumCases 30
```

## Building

Dependencies are pulled in as submodules, so clone recursively:

```
git clone --recursive https://github.com/emoose/idaxex.git
# or, if already cloned:
git submodule update --init --recursive
```

Then build with the Ninja generator from the repo root:

```
cmake -S . -B build -G Ninja
cmake --build build
```

The repository vendors the official IDA SDK through `3rdparty/ida-sdk`. For a
warning-focused compatibility build, configure with
`-DIDAXEX_STRICT_WARNINGS=ON`. On Windows, the environment and vendored SDK can
be checked before building:

```powershell
scripts\Check-IdaEnv.ps1 `
  -IdaExe "C:\Program Files\IDA Professional 9.4\ida.exe" `
  -ExpectedIdaVersion 9.4 `
  -ExpectedSdkVersion 940 `
  -ExpectedSdkTag v9.4.0-release `
  -RequireOfficialSdk `
  -RequireBuildReady
```

This builds the loader at `build/bin/loaders/` (`idaxex.dll` on Windows,
`idaxex.so` on Linux, `idaxex.dylib` on macOS). To install it into IDA's
per-user directory so it's picked up automatically, run:

```
cmake --install build
```

- **Windows:** run the commands from a Visual Studio Developer Command Prompt
  (or any shell where `cl.exe` is on `PATH`).
- To build `xex1tool`, run `cmake -S xex1tool -B xex1tool/build -G Ninja` and
  `cmake --build xex1tool/build`.

## Credits
Based on work by the Xenia project, XEX2.bt by Anthony, xextool 0.1 by xor37h, Xex Loader & x360_imports.idc by xorloser, xkelib, XeCLI, and probably many others I forgot to name.

Thanks to everyone involved in the Xbox 360 modding/reverse-engineering community!

XTLID parsing supported thanks to the [XboxDev/xtlid project](https://github.com/XboxDev/xtlid).

# xex1tool
Also included is an attempt at recreating xorloser's XexTool, for working with older pre-XEX2 executables.  
(The name is only to differentiate it from the original XexTool - it'll still support XEX2 files fine)

So far it can print info about the various XEX headers via `-l`, and extract the basefile (PE/XUIZ) from inside the XEX.

For XEX files that are both decrypted & decompressed xex1tool can also convert a VA address to a file offset for you, making file patching a little easier.
