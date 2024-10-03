#pragma once
#include <cstdint>

#define EXE_MZ_SIGNATURE 0x5A4D
#define EXE_NT_SIGNATURE 0x4550

typedef struct _IMAGE_DOS_HEADER
{
  uint16_t MZSignature;
  uint16_t UsedBytesInTheLastPage;
  uint16_t FileSizeInPages;
  uint16_t NumberOfRelocationItems;
  uint16_t HeaderSizeInParagraphs;
  uint16_t MinimumExtraParagraphs;
  uint16_t MaximumExtraParagraphs;
  uint16_t InitialRelativeSS;
  uint16_t InitialSP;
  uint16_t Checksum;
  uint16_t InitialIP;
  uint16_t InitialRelativeCS;
  uint16_t AddressOfRelocationTable;
  uint16_t OverlayNumber;
  uint16_t Reserved[4];
  uint16_t OEMid;
  uint16_t OEMinfo;
  uint16_t Reserved2[10];
  uint32_t AddressOfNewExeHeader;
} IMAGE_DOS_HEADER;
static_assert(sizeof(IMAGE_DOS_HEADER) == 0x40, "IMAGE_DOS_HEADER");

//
// Directory format.
//

typedef struct _IMAGE_DATA_DIRECTORY {
  uint32_t VirtualAddress;
  uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
static_assert(sizeof(IMAGE_DATA_DIRECTORY) == 8, "IMAGE_DATA_DIRECTORY");

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER32
{
  uint16_t Magic;
  uint8_t  MajorLinkerVersion;
  uint8_t  MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint32_t BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;
static_assert(sizeof(IMAGE_OPTIONAL_HEADER32) == 0xE0, "IMAGE_OPTIONAL_HEADER32");

typedef struct _IMAGE_FILE_HEADER
{
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
} IMAGE_FILE_HEADER;
static_assert(sizeof(IMAGE_FILE_HEADER) == 0x14, "IMAGE_FILE_HEADER");

typedef struct _IMAGE_NT_HEADERS
{
  uint32_t Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS;
static_assert(sizeof(IMAGE_NT_HEADERS) == 0xF8, "IMAGE_NT_HEADERS");

typedef struct _IMAGE_SECTION_HEADER
{
  char Name[8];
  uint32_t VirtualSize;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLineNumbers;
  uint32_t Characteristics;
} IMAGE_SECTION_HEADER;
static_assert(sizeof(IMAGE_SECTION_HEADER) == 0x28, "IMAGE_SECTION_HEADER");

// Characteristics flags
#define IMAGE_SCN_CNT_CODE 0x20
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x40
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x80
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

// Data directory indices
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
  union {
    uint32_t Characteristics; // 0 for terminating null import descriptor
    uint32_t OriginalFirstThunk; // RVA to INT
  };
  uint32_t TimeDateStamp; // Time/Date of module, or other properties (see below)
  uint32_t ForwarderChain; // Forwarder chain ID
  uint32_t Name; // Module name
  uint32_t FirstThunk; // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;
static_assert(sizeof(IMAGE_IMPORT_DESCRIPTOR) == 0x14, "IMAGE_IMPORT_DESCRIPTOR");

typedef struct _IMAGE_EXPORT_DIRECTORY
{
  uint32_t Characteristics;
  uint32_t TimeDateStamp;
  uint16_t MajorVersion;
  uint16_t MinorVersion;
  uint32_t Name;
  uint32_t Base;
  uint32_t NumberOfFunctions;
  uint32_t NumberOfNames;
  uint32_t AddressOfFunctions;
  uint32_t AddressOfNames;
  uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
static_assert(sizeof(IMAGE_EXPORT_DIRECTORY) == 0x28, "IMAGE_EXPORT_DIRECTORY");

typedef struct _IMAGE_DEBUG_DIRECTORY {
  uint32_t Characteristics;
  uint32_t TimeDateStamp;
  uint16_t MajorVersion;
  uint16_t MinorVersion;
  uint32_t Type;
  uint32_t SizeOfData;
  uint32_t AddressOfRawData;
  uint32_t PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, * PIMAGE_DEBUG_DIRECTORY;
static_assert(sizeof(IMAGE_DEBUG_DIRECTORY) == 0x1C, "IMAGE_DEBUG_DIRECTORY");

#define CV_INFO_RSDS_SIGNATURE 0x53445352
struct CV_INFO_PDB70
{
  uint32_t CvSignature;
  uint8_t Signature[0x10];
  uint32_t Age;
  // followed by filename
  //BYTE PdbFileName[];
};
static_assert(sizeof(CV_INFO_PDB70) == 0x18, "CV_INFO_PDB70");
