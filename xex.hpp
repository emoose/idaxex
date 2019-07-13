#pragma once
#include <assert.h>

#define XEX2_MAGIC 0x32584558

#define XEX_HEADER_STRUCT(key, struct) (((key) << 8) | (sizeof (struct) >> 2))
#define XEX_HEADER_FIXED_SIZE(key, size) (((key) << 8) | ((size) >> 2))
#define XEX_HEADER_ULONG(key) (((key) << 8) | 1)
#define XEX_HEADER_FLAG(key) ((key) << 8)
#define XEX_HEADER_SIZEDSTRUCT(key) (((key) << 8) | 0xFF)
#define XEX_HEADER_STRING(key) XEX_HEADER_SIZEDSTRUCT(key)

#define XEX_HEADER_SECTION_TABLE XEX_HEADER_SIZEDSTRUCT(2)

#define XEX_FILE_DATA_DESCRIPTOR_HEADER XEX_HEADER_SIZEDSTRUCT(3)

#define XEX_PATCH_FILE_BASE_REFERENCE XEX_HEADER_FIXED_SIZE(4, 20)

#define XEX_HEADER_DELTA_PATCH_DESCRIPTOR XEX_HEADER_SIZEDSTRUCT(5)

#define XEX_HEADER_BOUND_PATH XEX_HEADER_STRING(0x0080)

#define XEX_HEADER_ORIGINAL_BASE_ADDRESS XEX_HEADER_ULONG(0x0100)

#define XEX_HEADER_ENTRY_POINT XEX_HEADER_FLAG(0x0101)

#define XEX_HEADER_PE_BASE XEX_HEADER_ULONG(0x0102)

typedef struct _XEX_IMPORT_DESCRIPTOR {
  uint32 Size;
  uint32 NameTableSize;
  uint32 ModuleCount;
} XEX_IMPORT_DESCRIPTOR, *PXEX_IMPORT_DESCRIPTOR;

#define XEX_HEADER_IMPORTS XEX_HEADER_SIZEDSTRUCT(0x0103)

typedef struct _XEX_IMPORT_TABLE {
  uint32 TableSize;
  uint8 NextImportDigest[0x14];
  uint32 ModuleNumber;
  uint32 Version[2];
  uint8 Unused;
  uint8 ModuleIndex;
  uint16 ImportCount;
} XEX_IMPORT_TABLE, *PXEX_IMPORT_TABLE;

typedef struct _HV_IMAGE_EXPORT_TABLE {
  uint32 Magic[3];
  uint32 ModuleNumber[2];
  uint32 Version[3];
  uint32 ImageBaseAddress;
  uint32 Count;
  uint32 Base;
} HV_IMAGE_EXPORT_TABLE, *PHV_IMAGE_EXPORT_TABLE;

#define XEX_EXPORT_MAGIC_0      0x48000000
#define XEX_EXPORT_MAGIC_1      0x00485645
#define XEX_EXPORT_MAGIC_2      0x48000000

typedef struct _IMAGE_XEX_HEADER {
  uint32 Magic; // 0x0 sz:0x4
  uint32 ModuleFlags; // 0x4 sz:0x4
  uint32 SizeOfHeaders; // 0x8 sz:0x4
  uint32 SizeOfDiscardableHeaders; // 0xC sz:0x4
  uint32 SecurityInfo; // 0x10 sz:0x4
  uint32 HeaderDirectoryEntryCount; // 0x14 sz:0x4
} IMAGE_XEX_HEADER, *PIMAGE_XEX_HEADER; // size 24
static_assert(sizeof(IMAGE_XEX_HEADER) == 0x18, "IMAGE_XEX_HEADER");

typedef struct _IMAGE_XEX_DIRECTORY_ENTRY {
  uint32 Key; // 0x0 sz:0x4
  uint32 Value; // 0x4 sz:0x4
} IMAGE_XEX_DIRECTORY_ENTRY, *PIMAGE_XEX_DIRECTORY_ENTRY; // size 8
static_assert(sizeof(IMAGE_XEX_DIRECTORY_ENTRY) == 8, "IMAGE_XEX_DIRECTORY_ENTRY");

typedef struct _XEX2_HV_IMAGE_INFO {
  uint8 Signature[0x100];
  uint32 InfoSize;
  uint32 ImageFlags;
  uint32 LoadAddress;
  uint8 ImageHash[0x14];
  uint32 ImportTableCount;
  uint8 ImportDigest[0x14];
  uint8 MediaID[0x10];
  uint8 ImageKey[0x10];
  uint32 ExportTableAddress;
  uint8 HeaderHash[0x14];
  uint32 GameRegion;
} XEX2_HV_IMAGE_INFO, *PXEX2_HV_IMAGE_INFO;

typedef struct _XEX2_SECURITY_INFO {
  uint32 Size;
  uint32 ImageSize;
  XEX2_HV_IMAGE_INFO ImageInfo;
  uint32 AllowedMediaTypes;
  uint32 PageDescriptorCount;
} XEX2_SECURITY_INFO, *PXEX2_SECURITY_INFO;

typedef struct _XEX_FILE_DATA_DESCRIPTOR {
  uint32 Size;
  uint16 Flags;
  uint16 Format;
} XEX_FILE_DATA_DESCRIPTOR, *PXEX_FILE_DATA_DESCRIPTOR;

// After XEX_FILE_DATA_DESCRIPTOR when Format == 1 (aka "uncompressed")
typedef struct _XEX_RAW_DATA_DESCRIPTOR {
  uint32 DataSize;
  uint32 ZeroSize;
} XEX_RAW_DATA_DESCRIPTOR, *PXEX_RAW_DATA_DESCRIPTOR;

// After XEX_FILE_DATA_DESCRIPTOR when Format == 2 (aka compressed)
// (first block has WindowSize prepended to it!)
typedef struct _XEX_DATA_DESCRIPTOR {
  uint32 Size;
  uint8 DataDigest[0x14];
} XEX_DATA_DESCRIPTOR, *PXEX_DATA_DESCRIPTOR;

typedef struct _XEX_COMPRESSED_DATA_DESCRIPTOR {
  uint32 WindowSize;
  XEX_DATA_DESCRIPTOR FirstDescriptor;
} XEX_COMPRESSED_DATA_DESCRIPTOR, *P_XEX_COMPRESSED_DATA_DESCRIPTOR;

typedef struct _IMAGE_DOS_HEADER
{
  uint16 MZSignature;
  uint16 UsedBytesInTheLastPage;
  uint16 FileSizeInPages;
  uint16 NumberOfRelocationItems;
  uint16 HeaderSizeInParagraphs;
  uint16 MinimumExtraParagraphs;
  uint16 MaximumExtraParagraphs;
  uint16 InitialRelativeSS;
  uint16 InitialSP;
  uint16 Checksum;
  uint16 InitialIP;
  uint16 InitialRelativeCS;
  uint16 AddressOfRelocationTable;
  uint16 OverlayNumber;
  uint16 Reserved[4];
  uint16 OEMid;
  uint16 OEMinfo;
  uint16 Reserved2[10];
  uint32 AddressOfNewExeHeader;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER32
{
  uint16 Magic;
  uint8  MajorLinkerVersion;
  uint8  MinorLinkerVersion;
  uint32 SizeOfCode;
  uint32 SizeOfInitializedData;
  uint32 SizeOfUninitializedData;
  uint32 AddressOfEntryPoint;
  uint32 BaseOfCode;
  uint32 BaseOfData;
  uint32 ImageBase;
  uint32 SectionAlignment;
  uint32 FileAlignment;
  uint16 MajorOperatingSystemVersion;
  uint16 MinorOperatingSystemVersion;
  uint16 MajorImageVersion;
  uint16 MinorImageVersion;
  uint16 MajorSubsystemVersion;
  uint16 MinorSubsystemVersion;
  uint32 Win32VersionValue;
  uint32 SizeOfImage;
  uint32 SizeOfHeaders;
  uint32 CheckSum;
  uint16 Subsystem;
  uint16 DllCharacteristics;
  uint32 SizeOfStackReserve;
  uint32 SizeOfStackCommit;
  uint32 SizeOfHeapReserve;
  uint32 SizeOfHeapCommit;
  uint32 LoaderFlags;
  uint32 NumberOfRvaAndSizes;
} IMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_FILE_HEADER
{
  uint16 Machine;
  uint16 NumberOfSections;
  uint32 TimeDateStamp;
  uint32 PointerToSymbolTable;
  uint32 NumberOfSymbols;
  uint16 SizeOfOptionalHeader;
  uint16 Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS
{
  uint32 Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER
{
  char Name[8];
  uint32 VirtualSize;
  uint32 VirtualAddress;
  uint32 SizeOfRawData;
  uint32 PointerToRawData;
  uint32 PointerToRelocations;
  uint32 PointerToLinenumbers;
  uint16 NumberOfRelocations;
  uint16 NumberOfLineNumbers;
  uint32 Characteristics;
} IMAGE_SECTION_HEADER;

// Characteristics flags
#define IMAGE_SCN_CNT_CODE 0x20
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x40
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x80
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000
