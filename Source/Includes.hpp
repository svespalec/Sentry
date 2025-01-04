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
  OUT PULONG ReturnLength OPTIONAL);
// clang-format on