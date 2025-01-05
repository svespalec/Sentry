# Sentry - Direct Syscall Detection Driver

A kernel driver that detects and blocks direct syscall attacks through thread monitoring.

## Overview

Modern malware often attempts to bypass EDR/AV solutions by implementing direct syscalls, avoiding the standard ntdll.dll stubs. 
Sentry prevents these techniques by detecting syscalls in threads outside of ntdll.dll.

## Features

**Core Functionality:**
- Thread creation monitoring (PsSetCreateThreadNotifyRoutineEx)
- ntdll.dll tracking via image loading notifications
- Memory analysis of thread regions
- Syscall instruction pattern detection

**Protection Mechanism:**
- Intercepts thread creation
- Validates syscall sources
- Blocks suspicious threads pre-execution
- Prevents EDR/AV bypasses

## Requirements

- Visual Studio 2022
- Latest Windows SDK
- Latest Windows Driver Kit (WDK)
