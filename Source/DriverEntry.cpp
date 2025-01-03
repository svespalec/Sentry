#include <ntdef.h>
#include <ntifs.h>

// Access mask definitions
#define THREAD_QUERY_INFORMATION (0x0040)

// Function declarations
EXTERN_C NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);
EXTERN_C NTSTATUS NTAPI NtQueryInformationThread(IN HANDLE ThreadHandle,
                                                 IN THREADINFOCLASS ThreadInformationClass,
                                                 OUT PVOID ThreadInformation,
                                                 IN ULONG ThreadInformationLength,
                                                 OUT PULONG ReturnLength OPTIONAL);

PVOID GetThreadStartAddress(PETHREAD Thread) {
  HANDLE ThreadHandle;
  PVOID StartAddress = NULL;
  BOOLEAN Result     = FALSE;

  // Get thread handle
  NTSTATUS status = ObOpenObjectByPointer(Thread, OBJ_KERNEL_HANDLE, NULL, THREAD_QUERY_INFORMATION,
                                          *PsThreadType, KernelMode, &ThreadHandle);

  if (!NT_SUCCESS(status)) {
    return FALSE;
  }

  // Query thread start address
  status = NtQueryInformationThread(ThreadHandle, ThreadQuerySetWin32StartAddress, &StartAddress,
                                    sizeof(PVOID), NULL);

  if (NT_SUCCESS(status)) {
    PEPROCESS Process = IoThreadToProcess(Thread);
    PVOID BaseAddress = PsGetProcessSectionBaseAddress(Process);

    if ((ULONG_PTR)StartAddress >= (ULONG_PTR)BaseAddress &&
        (ULONG_PTR)StartAddress < (ULONG_PTR)BaseAddress + 0x1000000) {
      Result = TRUE;
    }
  }

  ZwClose(ThreadHandle);

  return StartAddress;
}

VOID ThreadCreateCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
  UNREFERENCED_PARAMETER(ProcessId);
  UNREFERENCED_PARAMETER(ThreadId);

  if (!Create) return;

  PETHREAD Thread;
  if (!NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &Thread))) {
    return;
  }

  // Get and use thread start address
  PVOID StartAddress = GetThreadStartAddress(Thread);

  DbgPrint("New thread started at address: %p\n", StartAddress);

  ObDereferenceObject(Thread);  // Don't forget to dereference
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  PsSetCreateThreadNotifyRoutine(ThreadCreateCallback);

  return STATUS_SUCCESS;
}
