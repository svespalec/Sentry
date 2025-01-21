#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <wdm.h>
#include <fltKernel.h>
#include <wdmsec.h>
#include <ntstrsafe.h>

// Memory type definitions from WinNT.h
#ifndef MEM_MAPPED
#define MEM_MAPPED  0x40000
#endif

#ifndef MEM_IMAGE  
#define MEM_IMAGE   0x1000000
#endif

// Process/Thread access rights from WinNT.h
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ          (0x0010)
#endif

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION (0x0040)
#endif

// Windows base types if not defined
typedef unsigned long DWORD;
typedef void* LPVOID;
typedef const char* PCSTR;
typedef const wchar_t* PCWSTR;
typedef unsigned short WORD;
typedef unsigned char BYTE;

// Signature verification definitions
typedef struct _FILE_SIGNATURE_INFO {
    ULONG Flags;
    ULONG CertificateState;
    ULONG HashState;
    ULONG SignatureState;
    LARGE_INTEGER ValidFrom;
    LARGE_INTEGER ValidUntil;
} FILE_SIGNATURE_INFO, *PFILE_SIGNATURE_INFO;

// Function declarations
EXTERN_C_START

// Process/Thread functions
NTKERNELAPI PCHAR PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

// Thread information functions
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

EXTERN_C_END

// Global structure to store ntdll information
typedef struct _MONITOR_CONTEXT {
    PVOID NtdllBase;
    SIZE_T NtdllSize;
} MONITOR_CONTEXT, *PMONITOR_CONTEXT;

extern MONITOR_CONTEXT g_MonitorContext;

typedef struct _SYSCALL_PATTERN {
    UCHAR Pattern[2];
    SIZE_T Size;
} SYSCALL_PATTERN, *PSYSCALL_PATTERN;

// Known syscall instruction patterns
extern const SYSCALL_PATTERN SyscallPatterns[];

// Function declarations
VOID DumpMemoryAround(
    _In_reads_bytes_(Size) PUCHAR Buffer,
    _In_ SIZE_T Offset,
    _In_ SIZE_T Size
);

BOOLEAN ContainsSyscallInstruction(
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
);

PCCH GetProcessNameFromProcess(
    _In_ PEPROCESS Process
);

BOOLEAN IsProcessSigned(
    _In_ PEPROCESS Process
);

BOOLEAN IsAddressInProcessMemory(
    _In_ PVOID Address,
    _In_ PEPROCESS Process
);

#define IMAGE_DOS_SIGNATURE 0x5A4D     // MZ
#define IMAGE_NT_SIGNATURE 0x00004550  // PE00
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4

typedef struct _IMAGE_DOS_HEADER {
  WORD e_magic;     // Magic number (should be IMAGE_DOS_SIGNATURE)
  WORD e_cblp;      // Bytes on last page of file
  WORD e_cp;        // Pages in file
  WORD e_crlc;      // Relocations
  WORD e_cparhdr;   // Size of header in paragraphs
  WORD e_minalloc;  // Minimum extra paragraphs needed
  WORD e_maxalloc;  // Maximum extra paragraphs needed
  WORD e_ss;        // Initial (relative) SS value
  WORD e_sp;        // Initial SP value
  WORD e_csum;      // Checksum
  WORD e_ip;        // Initial IP value
  WORD e_cs;        // Initial (relative) CS value
  WORD e_lfarlc;    // File address of relocation table
  WORD e_ovno;      // Overlay number
  WORD e_res[4];    // Reserved words
  WORD e_oemid;     // OEM identifier
  WORD e_oeminfo;   // OEM information
  WORD e_res2[10];  // Reserved words
  LONG e_lfanew;    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
  WORD Machine;
  WORD NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD SizeOfOptionalHeader;
  WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  ULONGLONG ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

// Add RtlStringCb function declarations if not defined
#ifndef RtlStringCbPrintfA
NTSTRSAFEDDI
RtlStringCbPrintfA(
    _Out_writes_bytes_(cbDest) NTSTRSAFE_PSTR pszDest,
    _In_ size_t cbDest,
    _In_ _Printf_format_string_ NTSTRSAFE_PCSTR pszFormat,
    ...);
#endif

#ifndef RtlStringCbLengthA
NTSTRSAFEDDI
RtlStringCbLengthA(
    _In_reads_or_z_(cbMax) NTSTRSAFE_PCSTR psz,
    _In_ size_t cbMax,
    _Out_opt_ size_t* pcbLength);
#endif
