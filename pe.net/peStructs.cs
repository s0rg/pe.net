using System;
using System.Text;
using System.Runtime.InteropServices;

namespace pe.net
{
    #region File Header Structures

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_DOS_HEADER          // DOS .EXE header
    {
        public UInt16 e_magic;              // Magic number
        public UInt16 e_cblp;               // Bytes on last page of file
        public UInt16 e_cp;                 // Pages in file
        public UInt16 e_crlc;               // Relocations
        public UInt16 e_cparhdr;            // Size of header in paragraphs
        public UInt16 e_minalloc;           // Minimum extra paragraphs needed
        public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
        public UInt16 e_ss;                 // Initial (relative) SS value
        public UInt16 e_sp;                 // Initial SP value
        public UInt16 e_csum;               // Checksum
        public UInt16 e_ip;                 // Initial IP value
        public UInt16 e_cs;                 // Initial (relative) CS value
        public UInt16 e_lfarlc;             // File address of relocation table
        public UInt16 e_ovno;               // Overlay number
        public UInt16 e_res_0;              // Reserved words
        public UInt16 e_res_1;              // Reserved words
        public UInt16 e_res_2;              // Reserved words
        public UInt16 e_res_3;              // Reserved words
        public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
        public UInt16 e_oeminfo;            // OEM information; e_oemid specific
        public UInt16 e_res2_0;             // Reserved words
        public UInt16 e_res2_1;             // Reserved words
        public UInt16 e_res2_2;             // Reserved words
        public UInt16 e_res2_3;             // Reserved words
        public UInt16 e_res2_4;             // Reserved words
        public UInt16 e_res2_5;             // Reserved words
        public UInt16 e_res2_6;             // Reserved words
        public UInt16 e_res2_7;             // Reserved words
        public UInt16 e_res2_8;             // Reserved words
        public UInt16 e_res2_9;             // Reserved words
        public UInt32 e_lfanew;             // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_IMPORT_DESCRIPTOR
    {
        public UInt32 OriginalFirstThunk;
        public UInt32 TimeDateStamp;
        public UInt32 ForwarderChain;
        public UInt32 Name;
        public UInt32 FirstThunk;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_EXPORT_DIRECTORY
    {
        public UInt32 Characteristics;
        public UInt32 TimeDateStamp;
        public UInt16 MajorVersion;
        public UInt16 MinorVersion;
        public UInt32 Name;
        public UInt32 Base;
        public UInt32 NumberOfFunctions;
        public UInt32 NumberOfNames;
        public UInt32 AddressOfFunctions;
        public UInt32 AddressOfNames;
        public UInt32 AddressOfNameOrdinals;
    }

    public enum PeType : ushort
    {
        PE32 = 0x010B,
        PE64 = 0x020B,
        ROM = 0x0107
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt32 BaseOfData;
        public UInt32 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt32 SizeOfStackReserve;
        public UInt32 SizeOfStackCommit;
        public UInt32 SizeOfHeapReserve;
        public UInt32 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    public enum MachineType : ushort
    {
        IMAGE_FILE_MACHINE_UNKNOWN = 0x0000,
        IMAGE_FILE_MACHINE_AM33 = 0x1d3,
        IMAGE_FILE_MACHINE_AMD64 = 0x8664,
        IMAGE_FILE_MACHINE_ARM = 0x01c0,
        IMAGE_FILE_MACHINE_ARMV7 = 0x01c4,
        IMAGE_FILE_MACHINE_EBC = 0x0ebc,
        IMAGE_FILE_MACHINE_I386 = 0x014c,
        IMAGE_FILE_MACHINE_IA64 = 0x0200,
        IMAGE_FILE_MACHINE_M32R = 0x9041,
        IMAGE_FILE_MACHINE_MIPS1 = 0x0266,
        IMAGE_FILE_MACHINE_MIPSFPU = 0x0366,
        IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466,
        IMAGE_FILE_MACHINE_POWERPC = 0x01f0,
        IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1,
        IMAGE_FILE_MACHINE_R4000 = 0x0166,
        IMAGE_FILE_MACHINE_SH3 = 0x01a2,
        IMAGE_FILE_MACHINE_SH3DSP = 0x01a3,
        IMAGE_FILE_MACHINE_SH4 = 0x01a6,
        IMAGE_FILE_MACHINE_SH5 = 0x01a8,
        IMAGE_FILE_MACHINE_THUMB = 0x01c2,
        IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER
    {
        public MachineType Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public FileHeaderFlags Characteristics;
    }

    // Grabbed the following 2 definitions from 
	//	http://www.pinvoke.net/default.aspx/Structures/IMAGE_SECTION_HEADER.html

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] _Name;
        [FieldOffset(8)]
        public UInt32 VirtualSize;
        [FieldOffset(12)]
        public UInt32 VirtualAddress;
        [FieldOffset(16)]
        public UInt32 SizeOfRawData;
        [FieldOffset(20)]
        public UInt32 PointerToRawData;
        [FieldOffset(24)]
        public UInt32 PointerToRelocations;
        [FieldOffset(28)]
        public UInt32 PointerToLinenumbers;
        [FieldOffset(32)]
        public UInt16 NumberOfRelocations;
        [FieldOffset(34)]
        public UInt16 NumberOfLinenumbers;
        [FieldOffset(36)]
        public DataSectionFlags Characteristics;

        public string Name
        {
            get { return new String(_Name); }
        }
    }

    [Flags]
    public enum FileHeaderFlags : ushort
    {
        /// <summary>
        /// Relocation information was stripped from the file.
        /// The file must be loaded at its preferred base address.
        /// If the base address is not available, the loader reports an error.
        /// </summary>
        IMAGE_FILE_RELOCS_STRIPPED = 0x0001,

        /// <summary>
        /// The file is executable (there are no unresolved external references).
        /// </summary>
        IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,

        /// <summary>
        /// COFF line numbers were stripped from the file.
        /// </summary>
        IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,

        /// <summary>
        /// COFF symbol table entries were stripped from file.
        /// </summary>
        IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,

        /// <summary>
        /// Aggressively trim the working set. This value is obsolete.
        /// </summary>
        IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010,

        /// <summary>
        /// The application can handle addresses larger than 2 GB.
        /// </summary>
        IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,

        /// <summary>
        /// The bytes of the word are reversed. This flag is obsolete.
        /// </summary>
        IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,

        /// <summary>
        /// The computer supports 32-bit words.
        /// </summary>
        IMAGE_FILE_32BIT_MACHINE = 0x0100,

        /// <summary>
        /// Debugging information was removed and stored separately in another file.
        /// </summary>
        IMAGE_FILE_DEBUG_STRIPPED = 0x0200,

        /// <summary>
        /// If the image is on removable media, copy it to and run it from the swap file.
        /// </summary>
        IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,

        /// <summary>
        /// If the image is on the network, copy it to and run it from the swap file.
        /// </summary>
        IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,

        /// <summary>
        /// The image is a system file.
        /// </summary>
        IMAGE_FILE_SYSTEM = 0x1000,

        /// <summary>
        /// The image is a DLL file. While it is an executable file, it cannot be run directly.
        /// </summary>
        IMAGE_FILE_DLL = 0x2000,

        /// <summary>
        /// The file should be run only on a uniprocessor computer.
        /// </summary>
        IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,

        /// <summary>
        /// The bytes of the word are reversed. This flag is obsolete.
        /// </summary>
        IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
    }

    [Flags]
    public enum DataSectionFlags : uint
    {
        /// <summary>
        /// The section should not be padded to the next boundary.
        /// This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES.
        /// </summary>
        IMAGE_SCN_TYPE_NO_PAD = 0x00000008,

        /// <summary>
        /// The section contains executable code.
        /// </summary>
        IMAGE_SCN_CNT_CODE = 0x00000020,

        /// <summary>
        /// The section contains initialized data.
        /// </summary>
        IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,

        /// <summary>
        /// The section contains uninitialized data.
        /// </summary>
        IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,

        /// <summary>
        /// Reserved.
        /// </summary>
        IMAGE_SCN_LNK_OTHER = 0x00000100,

        /// <summary>
        /// The section contains comments or other information.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_LNK_INFO = 0x00000200,

        /// <summary>
        /// The section will not become part of the image.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_LNK_REMOVE = 0x00000800,

        /// <summary>
        /// The section contains COMDAT data.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_LNK_COMDAT = 0x00001000,

        /// <summary>
        /// Reset speculative exceptions handling bits in the TLB entries for this section.
        /// </summary>
        IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000,

        /// <summary>
        /// The section contains data referenced through the global pointer.
        /// </summary>
        IMAGE_SCN_GPREL = 0x00008000,

        /// <summary>
        /// Reserved.
        /// </summary>
        IMAGE_SCN_MEM_PURGEABLE = 0x00020000,

        /// <summary>
        /// Reserved.
        /// </summary>
        IMAGE_SCN_MEM_LOCKED = 0x00040000,

        /// <summary>
        /// Reserved.
        /// </summary>
        IMAGE_SCN_MEM_PRELOAD = 0x00080000,

        /// <summary>
        /// Align data on a 1-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_1BYTES = 0x00100000,

        /// <summary>
        /// Align data on a 2-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_2BYTES = 0x00200000,

        /// <summary>
        /// Align data on a 4-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_4BYTES = 0x00300000,

        /// <summary>
        /// Align data on a 8-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_8BYTES = 0x00400000,

        /// <summary>
        /// Align data on a 16-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_16BYTES = 0x00500000,

        /// <summary>
        /// Align data on a 32-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_32BYTES = 0x00600000,

        /// <summary>
        /// Align data on a 64-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_64BYTES = 0x00700000,

        /// <summary>
        /// Align data on a 128-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_128BYTES = 0x00800000,

        /// <summary>
        /// Align data on a 256-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_256BYTES = 0x00900000,

        /// <summary>
        /// Align data on a 512-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,

        /// <summary>
        /// Align data on a 1024-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,

        /// <summary>
        /// Align data on a 2048-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,

        /// <summary>
        /// Align data on a 4096-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,

        /// <summary>
        /// Align data on a 8192-byte boundary.
        /// This is valid only for object files.
        /// </summary>
        IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,

        /// <summary>
        /// The section contains extended relocations.
        /// The count of relocations for the section exceeds the 16 bits that is reserved for it in the section header.
        /// If the NumberOfRelocations field in the section header is 0xffff, the actual relocation count is stored in
        /// the VirtualAddress field of the first relocation.
        /// It is an error if IMAGE_SCN_LNK_NRELOC_OVFL is set and there are fewer than 0xffff relocations in the
        /// section.
        /// </summary>
        IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,

        /// <summary>
        /// The section can be discarded as needed.
        /// </summary>
        IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,

        /// <summary>
        /// The section cannot be cached.
        /// </summary>
        IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,

        /// <summary>
        /// The section cannot be paged.
        /// </summary>
        IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,

        /// <summary>
        /// The section can be shared in memory.
        /// </summary>
        IMAGE_SCN_MEM_SHARED = 0x10000000,

        /// <summary>
        /// The section can be executed as code.
        /// </summary>
        IMAGE_SCN_MEM_EXECUTE = 0x20000000,

        /// <summary>
        /// The section can be read.
        /// </summary>
        IMAGE_SCN_MEM_READ = 0x40000000,

        /// <summary>
        /// The section can be written to.
        /// </summary>
        IMAGE_SCN_MEM_WRITE = 0x80000000
    }

    /*
     Find compatible names!
     */

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_BASE_RELOCATION
    {
        public UInt32 VirtualAddress;
        public UInt32 BlockSizeInclusive;
    }

    public struct Relocation
    {
        public UInt32 VirtualAddress;
        public RelocationType Type;
    }

    public enum RelocationType : byte
    {
        Absolute = 0,
        High = 1,
        Low = 2,
        HighLow = 3,
        HighAdj = 4,
        MIPS_JmpAddr = 5,
        Section = 6,
        Rel32 = 7
    }

    #endregion File Header Structures
}

