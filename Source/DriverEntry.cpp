#include "Includes.hpp"

// clang-format off

// Image load notification callback
VOID ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
  UNREFERENCED_PARAMETER(ProcessId);

  // Check if the loaded image is ntdll.dll
  if (FullImageName && FullImageName->Buffer && wcsstr(FullImageName->Buffer, L"\\ntdll.dll")) {
    g_MonitorContext.NtdllBase = ImageInfo->ImageBase;
    g_MonitorContext.NtdllSize = ImageInfo->ImageSize;

    DbgPrint("[Sentry]: ntdll.dll loaded at 0x%p with size 0x%zx\n", 
      g_MonitorContext.NtdllBase,          
      g_MonitorContext.NtdllSize
    );
  }
}

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
    &ThreadHandle);

  if (!NT_SUCCESS(Status)) 
    return NULL;

  // Query thread start address
  Status = ZwQueryInformationThread(
    ThreadHandle, 
    ThreadQuerySetWin32StartAddress, 
    &StartAddress,                                
    sizeof(PVOID), 
    NULL);

  ZwClose(ThreadHandle);

  if (!NT_SUCCESS(Status)) 
    return NULL;

  return StartAddress;
}

// Simple check if an address is within ntdll.dll (usermode)
BOOLEAN IsAddressInNtdll(PVOID Address) {
  if (!g_MonitorContext.NtdllBase || !g_MonitorContext.NtdllSize) {
    DbgPrint("[Sentry]: Warning - NtdllBase/Size not initialized\n");
    return FALSE;
  }

  DbgPrint("[Sentry]: Checking address 0x%p against ntdll range: 0x%p - 0x%p\n", 
    Address,
    g_MonitorContext.NtdllBase,
    (ULONG_PTR)g_MonitorContext.NtdllBase + g_MonitorContext.NtdllSize
  );

  return (
    (ULONG_PTR)Address >= (ULONG_PTR)g_MonitorContext.NtdllBase && 
    (ULONG_PTR)Address < (ULONG_PTR)g_MonitorContext.NtdllBase + g_MonitorContext.NtdllSize
  );
}

NTSTATUS IsMaliciousThread(PVOID StartAddress, PEPROCESS Process) {
  // Verifies IRQL is PASSIVE_LEVEL
  PAGED_CODE();

  // Skip system process
  if (PsGetProcessId(Process) <= (HANDLE)4) 
    return STATUS_SUCCESS;

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

    // Block the thread
    return STATUS_ACCESS_DENIED; 
  }

  // Allocate buffer for entire region
  PVOID buffer = ExAllocatePool2(POOL_FLAG_PAGED, MemInfo.RegionSize, 'scan');

  if (!buffer) {
    KeUnstackDetachProcess(&ApcState);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Safely copy the thread contents for analysis
  // => StartAddress to StartAddress+MemInfo.RegionSize
  RtlZeroMemory(buffer, MemInfo.RegionSize);
  ProbeForRead(StartAddress, MemInfo.RegionSize, sizeof(UCHAR));
  RtlCopyMemory(buffer, StartAddress, MemInfo.RegionSize);

  if (ContainsSyscallInstruction(buffer, MemInfo.RegionSize)) {
    DbgPrint("[Sentry]: IOC => Detected syscall pattern in thread at 0x%p\n", StartAddress);

    // Block the thread
    Status = STATUS_ACCESS_DENIED;  
  } else {
    Status = STATUS_SUCCESS;
  }

  ExFreePoolWithTag(buffer, 'scan');
  KeUnstackDetachProcess(&ApcState);

  return Status;
}

VOID ThreadCreateCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
  // If this isn't a thread being created, skip
  if (!Create) 
    return;

  // Skip if NTDLL info is not yet available
  if (!g_MonitorContext.NtdllBase || !g_MonitorContext.NtdllSize) {
    DbgPrint("[Sentry]: Skipping thread check - NTDLL info not yet available\n");
    return;
  }

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
    DbgPrint(
      "[Sentry]: IOC => Thread 0x%p has invalid/hidden start address." 
      "Terminating thread\n",
       ThreadId
    );

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
  NTSTATUS status;

  // Register image load callback
  status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[Sentry]: Failed to register image load callback (0x%08X)\n", status);
    return status;
  }

  // Register thread creation callback
  status = PsSetCreateThreadNotifyRoutine(ThreadCreateCallback);

  if (!NT_SUCCESS(status)) {
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    DbgPrint("[Sentry]: Failed to register thread callback (0x%08X)\n", status);
    return status;
  }

  return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
  PsRemoveCreateThreadNotifyRoutine(ThreadCreateCallback);

  DbgPrint("[Sentry]: Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  DriverObject->DriverUnload = DriverUnload;
  DbgPrint("[Sentry]: Loaded driver!\n");

  return RegisterCallbacks();
}
// clang-format on
