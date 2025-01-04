#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <wdm.h>

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

BOOLEAN ContainsSyscallInstruction(PVOID Buffer, SIZE_T Size) {
  PUCHAR ByteBuffer = (PUCHAR)Buffer;

  // Scan through the buffer looking for syscall patterns
  for (SIZE_T i = 0; i < Size - 1; i++) {
    for (SIZE_T j = 0; j < ARRAYSIZE(SyscallPatterns); j++) {
      if (RtlCompareMemory(&ByteBuffer[i], SyscallPatterns[j].Pattern, SyscallPatterns[j].Size) ==
          SyscallPatterns[j].Size) {
        return TRUE;
      }
    }
  }

  return FALSE;
}

PCCH GetProcessNameFromProcess(PEPROCESS Process) {
  return (PCCH)PsGetProcessImageFileName(Process);
}
