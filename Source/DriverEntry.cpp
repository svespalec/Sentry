#include "Includes.hpp"

// clang-format off

// Global variable definitions
MONITOR_CONTEXT g_MonitorContext = { 0 };
KSPIN_LOCK g_OutputLock;
KIRQL g_OldIrql;

// Known syscall instruction patterns
const SYSCALL_PATTERN SyscallPatterns[] = {
    { { 0x0F, 0x05 }, 2 },  // syscall
    { { 0xCD, 0x2E }, 2 }   // int 2Eh
};

// Helper function to synchronize output
VOID SynchronizedPrint(PCCH Format, ...) {
    va_list Args;
    va_start(Args, Format);
    
    // Acquire spinlock
    KeAcquireSpinLock(&g_OutputLock, &g_OldIrql);
    
    // Print the message
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, Format, Args);
    
    // Small delay to ensure output is flushed
    KeStallExecutionProcessor(100);
    
    // Release spinlock
    KeReleaseSpinLock(&g_OutputLock, g_OldIrql);
    
    va_end(Args);
}

// Helper function implementations
VOID DumpMemoryAround(PUCHAR Buffer, SIZE_T Offset, SIZE_T Size) {
    const SIZE_T CONTEXT_BYTES = 8;
    SIZE_T StartOffset = (Offset > CONTEXT_BYTES) ? Offset - CONTEXT_BYTES : 0;
    SIZE_T EndOffset = min(Offset + CONTEXT_BYTES, Size);
    CHAR HexDump[100] = {0};
    CHAR PatternMarkers[100] = {0};
    SIZE_T CurrentPos = 0;
    
    // Build hex dump string
    for (SIZE_T i = StartOffset; i < EndOffset; i++) {
        RtlStringCbPrintfA(&HexDump[CurrentPos], sizeof(HexDump) - CurrentPos, "%02X ", Buffer[i]);
        RtlStringCbPrintfA(&PatternMarkers[CurrentPos], sizeof(PatternMarkers) - CurrentPos, 
            i == Offset ? "^^ " : "   ");
        CurrentPos += 3;
    }

    // Pad both strings to align with border
    SIZE_T remaining = (16 - (EndOffset - StartOffset)) * 3;
    RtlFillMemory(&HexDump[CurrentPos], remaining, ' ');
    RtlFillMemory(&PatternMarkers[CurrentPos], remaining, ' ');
    HexDump[CurrentPos + remaining] = '\0';
    PatternMarkers[CurrentPos + remaining] = '\0';

    SynchronizedPrint("| Memory Analysis                                                             |\n");
    SynchronizedPrint("| - Syscall offset: 0x%-56zx |\n", Offset);
    SynchronizedPrint("| - Memory dump:  %-57s |\n", HexDump);
    SynchronizedPrint("| - Pattern at:   %-57s |\n", PatternMarkers);
}

BOOLEAN ContainsSyscallInstruction(PVOID Buffer, SIZE_T Size, SIZE_T* FoundOffset) {
    if (!Buffer || Size < 2) return FALSE;

    PUCHAR ByteBuffer = (PUCHAR)Buffer;

    // Scan through the buffer looking for syscall patterns
    for (SIZE_T i = 0; i <= Size - 2; i++) {
        for (SIZE_T j = 0; j < ARRAYSIZE(SyscallPatterns); j++) {
            if (i + SyscallPatterns[j].Size <= Size) {
                if (RtlCompareMemory(&ByteBuffer[i], SyscallPatterns[j].Pattern, SyscallPatterns[j].Size) ==
                    SyscallPatterns[j].Size) {
                    if (FoundOffset) *FoundOffset = i;
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

BOOLEAN ParsePECertificate(PUNICODE_STRING FilePath) {
    BOOLEAN hasValidCert = FALSE;
    HANDLE hFile;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    
    InitializeObjectAttributes(&objAttr,
                             FilePath,
                             OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                             NULL,
                             NULL);
                             
    NTSTATUS status = ZwOpenFile(&hFile,
                                FILE_READ_DATA | SYNCHRONIZE,
                                &objAttr,
                                &ioStatusBlock,
                                FILE_SHARE_READ,
                                FILE_SYNCHRONOUS_IO_NONALERT);
                                
    if (NT_SUCCESS(status)) {
        // Read DOS header first
        IMAGE_DOS_HEADER dosHeader;
        LARGE_INTEGER offset = {0};
        status = ZwReadFile(hFile, 
                          NULL,
                          NULL,
                          NULL,
                          &ioStatusBlock,
                          &dosHeader,
                          sizeof(IMAGE_DOS_HEADER),
                          &offset,
                          NULL);
                          
        if (NT_SUCCESS(status) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
            // Read NT headers
            IMAGE_NT_HEADERS64 ntHeaders;
            offset.QuadPart = dosHeader.e_lfanew;
            
            status = ZwReadFile(hFile,
                              NULL,
                              NULL,
                              NULL,
                              &ioStatusBlock,
                              &ntHeaders,
                              sizeof(IMAGE_NT_HEADERS64),
                              &offset,
                              NULL);
                              
            if (NT_SUCCESS(status) && ntHeaders.Signature == IMAGE_NT_SIGNATURE) {
                // Get security directory
                IMAGE_DATA_DIRECTORY securityDir = 
                    ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
                    
                if (securityDir.VirtualAddress && securityDir.Size) {
                    // Read certificate data
                    PVOID certData = ExAllocatePool2(POOL_FLAG_PAGED, securityDir.Size, 'treC');
                    if (certData) {
                        offset.QuadPart = securityDir.VirtualAddress;
                        
                        status = ZwReadFile(hFile,
                                          NULL,
                                          NULL,
                                          NULL,
                                          &ioStatusBlock,
                                          certData,
                                          securityDir.Size,
                                          &offset,
                                          NULL);
                                          
                        if (NT_SUCCESS(status)) {
                            // Certificate data exists and was read successfully
                            hasValidCert = TRUE;
                            
                            SynchronizedPrint("  - Certificate Details:\n");
                            SynchronizedPrint("    * Size: %lu bytes\n", securityDir.Size);
                            SynchronizedPrint("    * Location: 0x%08X\n", securityDir.VirtualAddress);
                        }
                        
                        ExFreePoolWithTag(certData, 'treC');
                    }
                }
            }
        }
        ZwClose(hFile);
    }
    return hasValidCert;
}

PCCH GetProcessNameFromProcess(PEPROCESS Process) {
    return (PCCH)PsGetProcessImageFileName(Process);
}

// Image load notification callback
VOID ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
  UNREFERENCED_PARAMETER(ProcessId);

  // Check if the loaded image is ntdll.dll
  if (FullImageName && FullImageName->Buffer && wcsstr(FullImageName->Buffer, L"\\ntdll.dll")) {
    g_MonitorContext.NtdllBase = ImageInfo->ImageBase;
    g_MonitorContext.NtdllSize = ImageInfo->ImageSize;

    SynchronizedPrint("[Sentry]: ntdll.dll loaded at 0x%p with size 0x%zx\n", 
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
    SynchronizedPrint("[Sentry] Warning: NtdllBase/Size not initialized\n");
    return FALSE;
  }

  // Removed separate DbgPrint for ntdll range check - it will be part of analysis blocks
  return (
    (ULONG_PTR)Address >= (ULONG_PTR)g_MonitorContext.NtdllBase && 
    (ULONG_PTR)Address < (ULONG_PTR)g_MonitorContext.NtdllBase + g_MonitorContext.NtdllSize
  );
}

BOOLEAN IsAddressInProcessMemory(PVOID Address, PEPROCESS Process) {
    KAPC_STATE ApcState = { 0 };
    MEMORY_BASIC_INFORMATION MemInfo{};
    BOOLEAN Result = FALSE;

    KeStackAttachProcess(Process, &ApcState);

    NTSTATUS Status = ZwQueryVirtualMemory(
        ZwCurrentProcess(),
        Address,
        MemoryBasicInformation,
        &MemInfo,
        sizeof(MemInfo),
        NULL
    );

    if (NT_SUCCESS(Status)) {
        Result = (MemInfo.State == MEM_COMMIT && 
                (MemInfo.Type == MEM_IMAGE || MemInfo.Type == MEM_MAPPED));
        
        // Format shorter memory range string
        CHAR RangeStr[50];
        RtlStringCbPrintfA(RangeStr, sizeof(RangeStr), 
            "0x%p", Address);
        SynchronizedPrint("| Valid memory address: %-54s |\n", RangeStr);
    }

    KeUnstackDetachProcess(&ApcState);
    return Result;
}

NTSTATUS IsMaliciousThread(PVOID StartAddress, PEPROCESS Process) {
    // Verifies IRQL is PASSIVE_LEVEL
    PAGED_CODE();

    // Skip system process
    if (PsGetProcessId(Process) <= (HANDLE)4) 
        return STATUS_SUCCESS;

    KAPC_STATE ApcState = { 0 };
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

    // Can't query region, which is highly suspicious
    if (!NT_SUCCESS(Status)) {
        KeUnstackDetachProcess(&ApcState);
        SynchronizedPrint("\n[Sentry]: IOC => Cannot query memory region at 0x%p, Status: 0x%X\n\n", 
            StartAddress,
            Status
        );
        return STATUS_ACCESS_DENIED;
    }

    // Allocate buffer for entire region
    PVOID buffer = ExAllocatePool2(POOL_FLAG_PAGED, MemInfo.RegionSize, 'scan');

    if (!buffer) {
        KeUnstackDetachProcess(&ApcState);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Safely copy the thread contents for analysis
    RtlZeroMemory(buffer, MemInfo.RegionSize);
    ProbeForRead(StartAddress, MemInfo.RegionSize, sizeof(UCHAR));
    RtlCopyMemory(buffer, StartAddress, MemInfo.RegionSize);

    SIZE_T SyscallOffset = 0;
    BOOLEAN HasSyscall = ContainsSyscallInstruction(buffer, MemInfo.RegionSize, &SyscallOffset);
    
    if (HasSyscall) {
        PCCH ProcessName = GetProcessNameFromProcess(Process);
        
        SynchronizedPrint("-------------------------------------------------------------------------------\n");
        SynchronizedPrint("| Direct Syscall Detection                                                     |\n");
        SynchronizedPrint("| Process: %-63s |\n", ProcessName);
        SynchronizedPrint("-------------------------------------------------------------------------------\n");
        
        // If it's in ntdll, allow it
        if (IsAddressInNtdll(StartAddress)) {
            SynchronizedPrint("| Security Analysis                                                            |\n");
            SynchronizedPrint("| - Start Address: 0x%-56p |\n", StartAddress);
            SynchronizedPrint("| - Memory Type:   NTDLL                                                      |\n");
            SynchronizedPrint("| - Signature:     Valid                                                      |\n");
            SynchronizedPrint("| - Status:        Allowed                                                    |\n");
            DumpMemoryAround((PUCHAR)buffer, SyscallOffset, MemInfo.RegionSize);
            SynchronizedPrint("-------------------------------------------------------------------------------\n\n");
            ExFreePoolWithTag(buffer, 'scan');
            KeUnstackDetachProcess(&ApcState);
            return STATUS_SUCCESS;
        }

        // Get process image path for certificate check
        PUNICODE_STRING ProcessImagePath = NULL;
        NTSTATUS PathStatus = SeLocateProcessImageName(Process, &ProcessImagePath);
        
        // Check if process is signed and address is in valid memory
        BOOLEAN IsSigned = FALSE;
        if (NT_SUCCESS(PathStatus) && ProcessImagePath != NULL) {
            IsSigned = ParsePECertificate(ProcessImagePath);
            ExFreePool(ProcessImagePath);
        }
        
        BOOLEAN IsValidMemory = IsAddressInProcessMemory(StartAddress, Process);

        SynchronizedPrint("| Security Analysis                                                            |\n");
        SynchronizedPrint("| - Start Address: 0x%-56p |\n", StartAddress);
        SynchronizedPrint("| - Memory Type:   %-56s |\n", IsValidMemory ? "Valid" : "Suspicious");
        SynchronizedPrint("| - Signature:     %-56s |\n", IsSigned ? "Valid" : "Invalid/Missing");
        SynchronizedPrint("| - Status:        %-56s |\n", (IsSigned && IsValidMemory) ? "Allowed" : "Blocked");
        DumpMemoryAround((PUCHAR)buffer, SyscallOffset, MemInfo.RegionSize);

        if (IsSigned && IsValidMemory) {
            SynchronizedPrint("-------------------------------------------------------------------------------\n\n");
            ExFreePoolWithTag(buffer, 'scan');
            KeUnstackDetachProcess(&ApcState);
            return STATUS_SUCCESS;
        }

        SynchronizedPrint("| Alert: Direct syscall detected in %s process with %s memory                  |\n",
            IsSigned ? "signed" : "unsigned",
            IsValidMemory ? "valid" : "suspicious");
        SynchronizedPrint("-------------------------------------------------------------------------------\n\n");
        
        ExFreePoolWithTag(buffer, 'scan');
        KeUnstackDetachProcess(&ApcState);
        return STATUS_ACCESS_DENIED;
    }

    ExFreePoolWithTag(buffer, 'scan');
    KeUnstackDetachProcess(&ApcState);
    return STATUS_SUCCESS;
}

VOID ThreadCreateCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    if (!Create) 
        return;

    if (!g_MonitorContext.NtdllBase || !g_MonitorContext.NtdllSize) {
        SynchronizedPrint("⚠️ [Sentry] Warning: NTDLL info not yet available - skipping thread check\n\n");
        return;
    }

    PEPROCESS Process = NULL;
    PETHREAD Thread = NULL;

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
        PCCH ProcessName = GetProcessNameFromProcess(Process);
        SynchronizedPrint("\nHidden Thread Detection\n");
        SynchronizedPrint("-------------------------------------------------------------------------------\n");
        SynchronizedPrint("| Process:    %-60s |\n", ProcessName);
        SynchronizedPrint("| Thread ID:  0x%-58p |\n", ThreadId);
        SynchronizedPrint("| Status:     Hidden/Invalid start address                                     |\n");
        SynchronizedPrint("| Action:     Thread blocked                                                   |\n");
        SynchronizedPrint("-------------------------------------------------------------------------------\n\n");
        ObDereferenceObject(Thread);
        ObDereferenceObject(Process);
        return;
    }

    // Skip analysis if thread is within ntdll
    if (IsAddressInNtdll(StartAddress)) {
        ObDereferenceObject(Process);
        ObDereferenceObject(Thread);
        return;
    }

    Status = IsMaliciousThread(StartAddress, Process);

    ObDereferenceObject(Thread);
    ObDereferenceObject(Process);
}

typedef struct _NOTIFY_CONTEXT {
    BOOLEAN HasValidSignature;
    UNICODE_STRING ImagePath;
} NOTIFY_CONTEXT, *PNOTIFY_CONTEXT;

VOID ProcessCreateCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    if (CreateInfo != NULL) {
        PUNICODE_STRING imagePath = NULL;
        if (NT_SUCCESS(SeLocateProcessImageName(Process, &imagePath))) {
            // Extract process name from full path
            UNICODE_STRING processName = *imagePath;
            for (USHORT i = imagePath->Length / sizeof(WCHAR); i > 0; i--) {
                if (imagePath->Buffer[i - 1] == L'\\') {
                    processName.Buffer = &imagePath->Buffer[i];
                    processName.Length = (imagePath->Length - (i * sizeof(WCHAR)));
                    processName.MaximumLength = processName.Length;
                    break;
                }
            }

            BOOLEAN hasCert = ParsePECertificate(imagePath);
            
            SynchronizedPrint("\nNew Process Created\n");
            SynchronizedPrint("-------------------------------------------------------------------------------\n");
            SynchronizedPrint("| Name: %-63wZ |\n", &processName);
            SynchronizedPrint("| PID:  %-63llu |\n", (ULONGLONG)ProcessId);
            SynchronizedPrint("| Path: %-63wZ |\n", imagePath);
            SynchronizedPrint("| Cert: %-63s |\n", hasCert ? "Valid" : "Invalid/Missing");
            SynchronizedPrint("-------------------------------------------------------------------------------\n\n");

            ExFreePool(imagePath);
        }
    }
}

NTSTATUS RegisterCallbacks() {
  NTSTATUS status;

  // Register image load callback
  status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);

  if (!NT_SUCCESS(status)) {
    SynchronizedPrint("[Sentry]: Failed to register image load callback (0x%08X)\n", status);
    return status;
  }

  // Register thread creation callback
  status = PsSetCreateThreadNotifyRoutine(ThreadCreateCallback);

  if (!NT_SUCCESS(status)) {
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    SynchronizedPrint("[Sentry]: Failed to register thread callback (0x%08X)\n", status);
    return status;
  }

    status = PsSetCreateProcessNotifyRoutineEx(
        (PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ProcessCreateCallback,
        FALSE
    );
    

  return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
  PsRemoveCreateThreadNotifyRoutine(ThreadCreateCallback);

      // Remove process creation callback
    PsSetCreateProcessNotifyRoutineEx(
        (PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ProcessCreateCallback,
        TRUE    // TRUE for removal
    );

  SynchronizedPrint("[Sentry]: Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  // Initialize the spinlock
  KeInitializeSpinLock(&g_OutputLock);

  DriverObject->DriverUnload = DriverUnload;
  SynchronizedPrint("[Sentry]: Loaded driver!\n\n");

  return RegisterCallbacks();
}
// clang-format on
