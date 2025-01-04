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
  Status = ZwQueryInformationThread(
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

// Callback for image load notifications
VOID ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
  UNREFERENCED_PARAMETER(ProcessId);

  // Check if the loaded image is ntdll.dll
  if (wcsstr(FullImageName->Buffer, L"\\ntdll.dll")) {
    g_MonitorContext.NtdllBase = ImageInfo->ImageBase;
    g_MonitorContext.NtdllSize = ImageInfo->ImageSize;

    DbgPrint("[Sentry]: ntdll.dll loaded at 0x%p with size 0x%zx\n", 
      g_MonitorContext.NtdllBase,
      g_MonitorContext.NtdllSize
    );
  }
}

// Simple check if an address is within NTDLL
BOOLEAN IsAddressInNtdll(PVOID Address) {
  if (!g_MonitorContext.NtdllBase || !g_MonitorContext.NtdllSize) 
    return FALSE;

  return ((ULONG_PTR)Address >= (ULONG_PTR)g_MonitorContext.NtdllBase &&
          (ULONG_PTR)Address < (ULONG_PTR)g_MonitorContext.NtdllBase + g_MonitorContext.NtdllSize);
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

  // Can't query region, which is highly suspicious and could be an Indicator of Compromise (IOC).
  // Malware often uses techniques to hide or protect its memory regions from inspection.
  if (!NT_SUCCESS(Status)) {
    KeUnstackDetachProcess(&ApcState);

    DbgPrint("[Sentry]: IOC => Cannot query memory region at 0x%p, Status: 0x%X\n", 
      StartAddress, 
      Status
    );

    return STATUS_ACCESS_DENIED; // Block the thread
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

 if (!StartAddress) {
    DbgPrint("[Sentry]: IOC => Thread 0x%p has invalid/hidden start address."
      "Terminating thread\n", 
      ThreadId
    );

    // TerminateThread(Thread);

    ObDereferenceObject(Thread);
    ObDereferenceObject(Process);
    return;
  }

  // If our thread is within ntdll, no need to check it
  if (IsAddressInNtdll(StartAddress)) {
    ObDereferenceObject(Process);
    ObDereferenceObject(Thread);
    return;
  }

  // Get process name
  PCCH ProcessName = GetProcessNameFromProcess(Process);

  DbgPrint("[Sentry]: Analyzing thread 0x%p in process %s (PID: %d) at address 0x%p\n",
    ThreadId,
    ProcessName,
    HandleToULong(ProcessId),
    StartAddress
  );

  Status = IsMaliciousThread(StartAddress, Process);
  DbgPrint("[Sentry]: Thread analysis result: %x\n", Status);

  ObDereferenceObject(Thread);
  ObDereferenceObject(Process);

  // Thread automatically resumes after callback if not terminated
  //
}

NTSTATUS RegisterCallbacks() {
  NTSTATUS Status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);

  if (!NT_SUCCESS(Status)) {
    DbgPrint("[Sentry]: ImageLoadCallback failure: 0x%X\n", Status);
    return Status;
  }

  // PsSetCreateThreadNotifyRoutineEx executes in suspended new thread context before
  // initialization, allowing for thread analysis and termination.
  Status = PsSetCreateThreadNotifyRoutineEx(
    PsCreateThreadNotifyNonSystem, 
    ThreadCreateCallback
  );

  if (!NT_SUCCESS(Status)) {
    DbgPrint("[Sentry]: ThreadCreateCallback failure: 0x%X\n", Status);
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    return Status;
  }

  return STATUS_SUCCESS;
}
// clang-format on

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  PsRemoveCreateThreadNotifyRoutine(ThreadCreateCallback);
  PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);

  DbgPrint("[Sentry]: Driver unloaded, all callbacks removed\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  DriverObject->DriverUnload = DriverUnload;
  DbgPrint("[Sentry]: Loaded driver!\n");

  return RegisterCallbacks();
}
