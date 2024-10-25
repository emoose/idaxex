#pragma once
#include <cstdint>
#include <cassert>

#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)

namespace xbe
{
  struct XbeInitFlags {
    /* 0x01 */ uint32_t MountUtilityDrive : 1;
    /* 0x02 */ uint32_t FormatUtilityDrive : 1;
    /* 0x04 */ uint32_t LimitDevkitMemory : 1;
    /* 0x08 */ uint32_t NoSetupHardDisk : 1;
    /* 0x10 */ uint32_t DontModifyHardDisk : 1;
    // Cluster size follows from 0x40000000 - 0xC0000000
  };
  static_assert(sizeof(XbeInitFlags) == 4, "xbe::XbeInitFlags");

  struct XbeHeader {
    uint32_t Signature;
    uint8_t EncryptedDigest[256];
    uint32_t BaseAddress;
    uint32_t SizeOfHeaders;
    uint32_t SizeOfImage;
    uint32_t SizeOfImageHeader;
    uint32_t TimeDateStamp;
    uint32_t CertificateOffset;
    uint32_t NumberOfSections;
    uint32_t SectionHeadersOffset;
    XbeInitFlags InitFlags;
    uint32_t AddressOfEntryPoint;
    uint32_t TlsDirectoryOffset;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t NtBaseOfDll;
    uint32_t NtSizeOfImage;
    uint32_t NtCheckSum;
    uint32_t NtTimeDateStamp;
    uint32_t DebugPathNameOffset;
    uint32_t DebugFileNameOffset;
    uint32_t DebugUnicodeFileNameOffset;
    uint32_t XboxKernelThunkDataOffset;
    uint32_t ImportDirectoryOffset;
    uint32_t NumberOfLibraryVersions;
    uint32_t LibraryVersionsOffset; // PXBEIMAGE_LIBRARY_VERSION
    uint32_t XboxKernelLibraryVersionOffset; // PXBEIMAGE_LIBRARY_VERSION
    uint32_t XapiLibraryVersionOffset; // PXBEIMAGE_LIBRARY_VERSION
    uint32_t MicrosoftLogoOffset;
    uint32_t SizeOfMicrosoftLogo;

    uint32_t LibraryFeaturesOffset; // PXBEIMAGE_LIBRARY_VERSION "only exists on XBEs built with an XDK version >= 5028."
    uint32_t NumberOfLibraryFeatures; // "only exists on XBEs built with an XDK version >= 5028."
    uint32_t CodeViewDebugInfoOffset; // "only exists on XBEs built with an XDK version >= 5455."
    
    inline bool has_library_features() { return SizeOfImageHeader >= 0x180; }
    inline bool has_codeview_offset() { return SizeOfImageHeader >= 0x184; }
  };
  static_assert(sizeof(XbeHeader) == 0x184, "xbe::XbeHeader");

  struct XbeSectionFlags
  {
    uint32_t Writable : 1;
    uint32_t Preload : 1;
    uint32_t Executable : 1;
    uint32_t InsertFile : 1;
    uint32_t HeadPageReadOnly : 1;
    uint32_t TailPageReadOnly : 1;
  };
  static_assert(sizeof(XbeSectionFlags) == 4, "xbe::XbeSectionFlags");

  struct XbeSection {
    XbeSectionFlags SectionFlags;
    uint32_t VirtualAddress;
    uint32_t VirtualSize;
    uint32_t PointerToRawData;
    uint32_t SizeOfRawData;
    uint32_t SectionNameOffset;
    uint32_t SectionReferenceCount;
    uint32_t HeadSharedPageReferenceCountOffset;
    uint32_t TailSharedPageReferenceCountOffset;
    uint8_t SectionDigest[20];
  };
  static_assert(sizeof(XbeSection) == 0x38, "xbe::XbeSection");

  struct XbeLibraryVersion {
    char LibraryName[8];
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t BuildVersion;
    uint16_t QFEVersion : 13;
    uint16_t ApprovedLibrary : 2;
    uint16_t DebugBuild : 1;
  };
  static_assert(sizeof(XbeLibraryVersion) == 0x10, "xbe::XbeLibraryVersion");

  struct ImageThunkData
  {
    union {
      uint32_t ForwarderString;      // PBYTE 
      uint32_t Function;             // PDWORD
      uint32_t Ordinal;
      uint32_t AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
  };
  static_assert(sizeof(ImageThunkData) == 4, "xbe::ImageThunkData");
};

namespace xe // Xbox alpha, based on 3521 structs
{
  struct XeOptionalHeader {
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t KernelVersion[4];
    uint16_t XAPIVersion[4];
    uint32_t InitFlags;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t TlsDirectory;
    uint16_t NumberOfModules;
    uint16_t NumberOfSections;
    uint16_t NumberOfDigests;
    uint16_t NumberOfImports;
    uint16_t SizeOfMiscData;
    uint16_t SizeOfCertInfo;
    uint16_t SizeOfEncHeaderDigest;
    uint16_t Reserved;
  };
  static_assert(sizeof(XeOptionalHeader) == 0x38, "xe::XeOptionalHeader");

  struct XeHeader {
    uint32_t Signature;
    uint32_t HeadersBase;
    uint32_t SectionsBase;
    uint32_t PagesInHeaders;
    uint32_t PagesInSections;
    uint32_t SizeOfImage;
    uint32_t SectionAlignment;
    uint32_t TimeDateStamp;
    uint32_t Checksum;
    uint32_t SizeOfOptionalHeader;
    XeOptionalHeader OptionalHeader;
  };
  static_assert(sizeof(XeHeader) == 0x60, "xe::XeHeader");

  struct XeModuleHeader {
    uint32_t ImageBase;
    uint32_t AddressOfEntryPoint;
    uint32_t ModuleFlags;
    uint32_t OrgSizeOfImage;
    uint32_t OrgCheckSum;
    uint32_t OrgTimestamp;
    uint16_t NameOfs;
    uint16_t DependStrOfs;
  };
  static_assert(sizeof(XeModuleHeader) == 0x1C, "xe::XeModuleHeader");

  struct XeImportHeader {
    uint16_t ExportModuleIndex;
    uint16_t ImportModuleIndex;
    uint32_t IATRVA;
    uint32_t Ordinal;
    uint32_t NameOfs;
  };
  static_assert(sizeof(XeImportHeader) == 0x10, "xe::XeImportHeader");

  struct XeSectionHeader {
    char Name[8];
    uint32_t VirtualAddress;
    uint32_t VirtualSize;
    uint16_t ModuleIndex;
    uint16_t SectionFlags;
    uint32_t HeadPage;
    uint32_t BodyPage;
    uint32_t TailPage;
  };
  static_assert(sizeof(XeSectionHeader) == 0x20, "xe::XeSectionHeader");

  struct XeXboxCert {
    uint16_t CertSig;
    uint16_t Reserved1;
    uint32_t TitleID;
    uint32_t SignatureTimeDate;
    uint32_t AllowedMedia;
    uint32_t ContentType;
    uint16_t ParentalControl;
    uint8_t GameRegion;
    uint8_t Reserved2;
    uint32_t AltTitleIds[16];
    wchar_t TitleName[40];
    wchar_t PublisherName[32];
  };
  static_assert(sizeof(XeXboxCert) == 0xE8, "xe::XeXboxCert");
};
