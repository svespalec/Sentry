#include "Includes.hpp"

// clang-format off
PVOID GetThreadStartAddress(PETHREAD Thread) {
  HANDLE ThreadHandle = NULL;
  PVOID StartAddress  = NULL;

  // Get thread handle
  NTSTATUS Status = ObOpenObjectByPointer(
    Thread, 
    OBJ_KERNEL_HANDLE, 
    NULL, 
    THREAD_QUERY_INFORMATION,                                        
    *PsThreadType, 
    KernelMode, 
    &ThreadHandle
  );

  if (!NT_SUCCESS(Status)) 
    return NULL;

  // Query thread start address
  Status = NtQueryInformationThread(
    ThreadHandle, 
    ThreadQuerySetWin32StartAddress, 
    &StartAddress,                                
    sizeof(PVOID), 
    NULL
  );

  ZwClose(ThreadHandle);

  if (!NT_SUCCESS(Status)) 
    return NULL;

  return StartAddress;
}

NTSTATUS IsMaliciousThread(PVOID StartAddress, PEPROCESS Process) {
  // Verifies IRQL is PASSIVE_LEVEL
  PAGED_CODE();

  KAPC_STATE ApcState = { 0 };
  SIZE_T RegionSize   = 0;
  MEMORY_BASIC_INFORMATION MemInfo{};

  // Attach to process context
  KeStackAttachProcess(Process, &ApcState);

  NTSTATUS Status = ZwQueryVirtualMemory(
    ZwCurrentProcess(),
    StartAddress,
    MemoryBasicInformation,                                      
    &MemInfo,
    sizeof(MemInfo), 
    NULL
  );

  // Can't query region. Highly suspicious.
  if (!NT_SUCCESS(Status)) {
    KeUnstackDetachProcess(&ApcState);
    return STATUS_SUCCESS;
  }

  // Allocate buffer for entire region
  PVOID buffer = ExAllocatePool2(
    POOL_FLAG_PAGED, 
    MemInfo.RegionSize, 
    'scan'
  );

  if (!buffer) {
    KeUnstackDetachProcess(&ApcState);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Safely copy the thread contents for analysis
  // => StartAddress to StartAddress+MemInfo.RegionSize
  RtlZeroMemory(buffer, MemInfo.RegionSize);
  ProbeForRead(StartAddress, MemInfo.RegionSize, sizeof(UCHAR));
  RtlCopyMemory(buffer, StartAddress, MemInfo.RegionSize);

  // Do checks on buffer here before freeing
  //
  //
  ExFreePoolWithTag(buffer, 'scan');

  KeUnstackDetachProcess(&ApcState);

  return STATUS_SUCCESS;
}

VOID ThreadCreateCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
  UNREFERENCED_PARAMETER(ProcessId);

  // If this isn't a thread being created, skip
  if (!Create) 
    return;

  PEPROCESS Process = NULL;
  PETHREAD Thread   = NULL;

  // Get both process and thread
  NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);

  if (!NT_SUCCESS(Status)) 
    return;

  Status = PsLookupThreadByThreadId(ThreadId, &Thread);

  if (!NT_SUCCESS(Status)) {
    ObDereferenceObject(Process);
    return;
  }

  PVOID StartAddress = GetThreadStartAddress(Thread);

  if (StartAddress) {
    // Pass the correct process
    Status = IsMaliciousThread(StartAddress, Process);
    DbgPrint("Thread analysis result: %x\n", Status);
  }

  ObDereferenceObject(Thread);
  ObDereferenceObject(Process);

  // Thread automatically resumes after callback if not terminated
  //
}
// clang-format on

/*
 * PsSetCreateThreadNotifyRoutineEx:
 * Executes in suspended new thread context before initialization,
 * allowing for thread analysis and optional blocking.
 */
NTSTATUS RegisterThreadCallback() {
  return PsSetCreateThreadNotifyRoutineEx(
      PsCreateThreadNotifyNonSystem,  // Only notify for non-system threads
      ThreadCreateCallback);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  return RegisterThreadCallback();
}
