# ProcessButcher  - Advanced Windows Threat Hunting Tool
## Download
[Download ProcessButcher v1.0](https://github.com/Oppenheim3r/ProcessButcher/releases/tag/ProcessButcher-1)

## Overview

ProcessButcher is a command-line tool designed for advanced threat hunting on Windows systems. It leverages the undocumented Windows Native API (primarily functions within `ntdll.dll`) to gather deep insights into running processes, their memory, threads, and handles, often revealing information hidden from standard tools.

This tool was developed based on concepts from Pavel Yosifovich's "Windows Native API Programming" book and general Windows Internals knowledge.

## Features

ProcessButcher provides the following analysis capabilities:

1.  **Deep Process Insights:** Enumerates running processes using `NtQuerySystemInformation`, displaying PID, Parent PID, Session ID, Handle Count, Thread Count, and Image Name.
2.  **PEB/TEB Parsing:** For each accessible process, it retrieves and parses:
    *   **Process Environment Block (PEB):** Extracts the full command line and image path name from `RTL_USER_PROCESS_PARAMETERS`.
    *   **Loaded Modules:** Enumerates loaded DLLs by walking the `InLoadOrderModuleList` within the `PEB_LDR_DATA`.
    *   **Thread Environment Block (TEB):** For each thread, it retrieves the TEB address using `NtQueryInformationThread` and displays stack base/limit information.
3.  **Memory Anomaly Detection:** Scans the virtual memory space of accessible processes using `NtQueryVirtualMemory` and flags potential anomalies:
    *   **RWX Private Memory:** Identifies private memory regions with Read-Write-Execute permissions.
    *   **Executable Non-Image Memory:** Flags executable memory regions that are not backed by a mapped image file (potential injected code).
4.  **Handle Analysis:** Enumerates handles owned by accessible processes using `NtQuerySystemInformation` (`SystemHandleInformation`). For each handle, it attempts to determine:
    *   **Handle Type:** Uses `NtDuplicateObject` and `NtQueryObject` (`ObjectTypeInformation`) to get the type name (e.g., "File", "Process", "Thread").
    *   **Object Name:** Uses `NtDuplicateObject` and `NtQueryObject` (`ObjectNameInformation`) to retrieve the name associated with the handle, if available.
5.  **Advanced Thread Analysis:** Integrates with process enumeration to display detailed thread information obtained from `SYSTEM_THREAD_INFORMATION`, including Thread ID (TID), Start Address, State, and Wait Reason.


## Usage

Run `ProcessButcher.exe` from a command prompt with Administrator privileges (required for `SeDebugPrivilege` and accessing other processes).

```bash
# Analyze all accessible processes
.\ProcessButcher.exe

# Analyze a specific process by PID
.\ProcessButcher.exe -p <PID>
.\ProcessButcher.exe -h
```

**Output:**

The tool will output detailed information for each analyzed process, including:
*   Basic process information.
*   PEB details (Command Line, Image Path).
*   Loaded modules list.
*   Thread list with TEB and stack info.
*   Memory region list with anomaly flags.
*   Handle list with type and object names.

## Important Notes

*   **Administrator Privileges:** Required for full functionality.
*   **Protected Processes:** ProcessButcher may not be able to open or analyze certain protected system processes (e.g., PPL processes). Warnings will be printed for processes that cannot be opened.
*   **Native API:** The tool relies heavily on undocumented Native APIs. Behavior might change between Windows versions. It was developed targeting Windows 10 (Redstone 2 era based on the book).
*   **Handle Query Hangs:** `NtQueryObject` for `ObjectNameInformation` can sometimes hang indefinitely, especially for certain pipe handles. A timeout mechanism (TODO Item 014) is not yet implemented.
*   **Error Handling:** Basic error handling is included, but further robustness improvements could be made.





