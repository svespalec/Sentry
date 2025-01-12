#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <wdm.h>

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
  ULONG NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef enum _SYSTEM_INFORMATION_CLASS {
  SystemBasicInformation  = 0,
  SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

#define THREAD_QUERY_INFORMATION (0x0040)

// clang-format off
EXTERN_C NTSTATUS NTAPI NtQueryInformationThread(
  IN HANDLE ThreadHandle,                                               
  IN THREADINFOCLASS ThreadInformationClass,                                               
  OUT PVOID ThreadInformation,                                                
  IN ULONG ThreadInformationLength,                                                
  OUT PULONG ReturnLength OPTIONAL
);

EXTERN_C NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(
  _In_ PEPROCESS Process
);

EXTERN_C NTSTATUS ZwQueryInformationThread(
 _In_ HANDLE ThreadHandle,
 _In_ THREADINFOCLASS ThreadInformationClass,
 _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
 _In_ ULONG ThreadInformationLength,
 _Out_opt_ PULONG ReturnLength
);

EXTERN_C NTSTATUS NTAPI ZwQuerySystemInformation(
  _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
  _In_ ULONG SystemInformationLength,
  _Out_opt_ PULONG ReturnLength
);

EXTERN_C NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
// clang-format on

// Global structure to store ntdll information
typedef struct _MONITOR_CONTEXT {
  PVOID NtdllBase;
  SIZE_T NtdllSize;
} MONITOR_CONTEXT, *PMONITOR_CONTEXT;

MONITOR_CONTEXT g_MonitorContext = { 0 };

typedef struct _SYSCALL_PATTERN {
  UCHAR Pattern[2];
  SIZE_T Size;
} SYSCALL_PATTERN, *PSYSCALL_PATTERN;

// Known syscall instruction patterns
const SYSCALL_PATTERN SyscallPatterns[] = {
  { { 0x0F, 0x05 }, 2 },  // syscall
  { { 0xCD, 0x2E }, 2 }   // int 2Eh
};
// Helper to dump bytes around pattern
VOID DumpMemoryAround(PUCHAR Buffer, SIZE_T Offset, SIZE_T Size) {
  const SIZE_T CONTEXT_BYTES = 16;  // Bytes to show before/after
  SIZE_T StartOffset         = (Offset > CONTEXT_BYTES) ? Offset - CONTEXT_BYTES : 0;
  SIZE_T EndOffset           = min(Offset + CONTEXT_BYTES, Size);

  DbgPrint("[Sentry]: Memory dump around offset 0x%zx:\n", Offset);
  for (SIZE_T i = StartOffset; i < EndOffset; i++) {
    DbgPrint("%02X ", Buffer[i]);
    if ((i - StartOffset + 1) % 16 == 0) DbgPrint("\n");
  }
  DbgPrint("\n");
}

BOOLEAN ContainsSyscallInstruction(PVOID Buffer, SIZE_T Size) {
  if (!Buffer || Size < 2) return FALSE;

  PUCHAR ByteBuffer = (PUCHAR)Buffer;

  // Scan through the buffer looking for syscall patterns
  for (SIZE_T i = 0; i <= Size - 2; i++) {
    for (SIZE_T j = 0; j < ARRAYSIZE(SyscallPatterns); j++) {
      if (i + SyscallPatterns[j].Size <= Size) {
        if (RtlCompareMemory(&ByteBuffer[i], SyscallPatterns[j].Pattern, SyscallPatterns[j].Size) ==
            SyscallPatterns[j].Size) {
          // Dump memory context around the pattern
          DumpMemoryAround(ByteBuffer, i, Size);
          return TRUE;
        }
      }
    }
  }
  return FALSE;
}

PCCH GetProcessNameFromProcess(PEPROCESS Process) {
  return (PCCH)PsGetProcessImageFileName(Process);
}
