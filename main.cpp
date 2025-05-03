// ProcessButcher - Advanced Windows Threat Hunting Tool

#define PHNT_VERSION PHNT_REDSTONE2

#include "phnt/phnt_windows.h"
#include "phnt/phnt.h"

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <iomanip>
#include <windows.h> 
#include <map> 
#include <sstream> 


std::wstring UnicodeStringToWstring(PUNICODE_STRING us) {
    if (us == nullptr || us->Buffer == nullptr || us->Length == 0) {
        return L"";
    }
    size_t len = us->Length;
    if (len % sizeof(WCHAR) != 0) {
        len -= (len % sizeof(WCHAR));
    }
    return std::wstring(us->Buffer, len / sizeof(WCHAR));
}


std::string ProtectionToString(ULONG protect) {
    std::string s = "";
    if (protect == 0) return "---";
    if (protect & PAGE_NOACCESS) s += "---";
    else if (protect & PAGE_READONLY) s += "R--";
    else if (protect & PAGE_READWRITE) s += "RW-";
    else if (protect & PAGE_WRITECOPY) s += "RC-";
    else if (protect & PAGE_EXECUTE) s += "--X";
    else if (protect & PAGE_EXECUTE_READ) s += "R-X";
    else if (protect & PAGE_EXECUTE_READWRITE) s += "RWX";
    else if (protect & PAGE_EXECUTE_WRITECOPY) s += "RCX";
    else s += "???";
    if (protect & PAGE_GUARD) s += "G"; else s += "-";
    if (protect & PAGE_NOCACHE) s += "N"; else s += "-";
    if (protect & PAGE_WRITECOMBINE) s += "C"; else s += "-";
    return s;
}


std::string MemoryTypeToString(ULONG type) {
    switch (type) {
        case MEM_PRIVATE: return "Private";
        case MEM_MAPPED: return "Mapped ";
        case MEM_IMAGE: return "Image  ";
        default: return "Unknown";
    }
}

std::string MemoryStateToString(ULONG state) {
    switch (state) {
        case MEM_COMMIT: return "Commit ";
        case MEM_RESERVE: return "Reserve";
        case MEM_FREE: return "Free   ";
        default: return "Unknown";
    }
}


std::map<USHORT, std::wstring> handleTypeMap;


BOOLEAN EnableDebugPrivilege();
void EnumerateAndAnalyzeProcesses(ULONG targetPid);
PPEB GetProcessPEB(HANDLE hProcess);
PTEB GetThreadTEB(HANDLE hThread);
NTSTATUS ReadProcessMemoryNative(HANDLE hProcess, PVOID baseAddress, PVOID buffer, SIZE_T size, PSIZE_T bytesRead);
void AnalyzeProcessPEB(HANDLE hProcess, HANDLE processId);
void AnalyzeProcessThreads(HANDLE hProcess, PSYSTEM_PROCESS_INFORMATION pSpi);
void AnalyzeProcessMemory(HANDLE hProcess, HANDLE processId);
void AnalyzeProcessHandles(HANDLE hProcess, HANDLE processId);
std::wstring GetHandleTypeName(HANDLE hProcess, HANDLE handle, USHORT typeIndex);
std::wstring GetHandleObjectName(HANDLE hProcess, HANDLE handle);
void PrintUsage();


int main(int argc, char* argv[]) {
    ULONG targetPid = 0; 

    std::cout << " ProcessButcher - Advanced Windows Threat Hunting Tool\n";
    std::cout << "=============================================\n\n";


    if (argc > 1) {
        if (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help") {
            PrintUsage();
            return 0;
        }
        if (std::string(argv[1]) == "-p" || std::string(argv[1]) == "--pid") {
            if (argc > 2) {
                try {
                    targetPid = std::stoul(argv[2]);
                    std::cout << "[INFO] Targeting specific process PID: " << targetPid << std::endl;
                } catch (const std::invalid_argument& e) {
                    std::cerr << "[ERROR] Invalid PID specified: " << argv[2] << std::endl;
                    PrintUsage();
                    return 1;
                } catch (const std::out_of_range& e) {
                    std::cerr << "[ERROR] PID out of range: " << argv[2] << std::endl;
                    PrintUsage();
                    return 1;
                }
            } else {
                std::cerr << "[ERROR] PID value missing after " << argv[1] << std::endl;
                PrintUsage();
                return 1;
            }
        } else {
            std::cerr << "[ERROR] Unknown option: " << argv[1] << std::endl;
            PrintUsage();
            return 1;
        }
    }

    try {
        if (EnableDebugPrivilege()) {
            std::cout << "[INFO] SeDebugPrivilege enabled successfully.\n";
        } else {
            std::cout << "[WARN] Failed to enable SeDebugPrivilege. Some operations might fail.\n";
        }

        std::cout << "\n[INFO] Starting Process Enumeration & Analysis...\n";
        EnumerateAndAnalyzeProcesses(targetPid); 

        std::cout << "\n[INFO] Analysis complete.\n";

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] An exception occurred: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "[ERROR] An unknown exception occurred." << std::endl;
        return 1;
    }

    return 0;
}

void PrintUsage() {
    std::cout << "Usage: ProcessButcher.exe [-p PID] [-h]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -p, --pid PID    Analyze only the specified process ID." << std::endl;
    std::cout << "  -h, --help       Show this help message." << std::endl;
    std::cout << "If no PID is specified, all accessible processes will be analyzed." << std::endl;
}


BOOLEAN EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return FALSE; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) { CloseHandle(hToken); return FALSE; }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) { CloseHandle(hToken); return FALSE; }
    CloseHandle(hToken);
    return TRUE;
}


void EnumerateAndAnalyzeProcesses(ULONG targetPid) {
    NTSTATUS status;
    ULONG bufferSize = 0;
    std::unique_ptr<BYTE[]> buffer;
    bool targetFound = false;

    status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
         throw std::runtime_error("NtQuerySystemInformation failed to get buffer size. Status: 0x" + std::to_string(status));
    }

    bufferSize += 1024 * 64; 
    buffer = std::make_unique<BYTE[]>(bufferSize);

    status = NtQuerySystemInformation(SystemProcessInformation, buffer.get(), bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("NtQuerySystemInformation failed to get process list. Status: 0x" + std::to_string(status));
    }


    std::wcout << std::left 
               << std::setw(10) << L"PID" 
               << std::setw(10) << L"ParentPID" 
               << std::setw(8) << L"Session" 
               << std::setw(10) << L"Handles" 
               << std::setw(8) << L"Threads" 
               << L"ImageName" << std::endl;
    std::wcout << std::wstring(80, L'-') << std::endl; 

    PSYSTEM_PROCESS_INFORMATION pSpi = (PSYSTEM_PROCESS_INFORMATION)buffer.get();

    while (pSpi) {
        HANDLE hProcess = nullptr;
        HANDLE currentPidHandle = pSpi->UniqueProcessId;
        ULONG currentPidUlong = HandleToULong(currentPidHandle);

        
        if (targetPid != 0 && currentPidUlong != targetPid) {
             if (pSpi->NextEntryOffset == 0) break;
             pSpi = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pSpi + pSpi->NextEntryOffset);
             continue;
        }
        if (targetPid != 0 && currentPidUlong == targetPid) {
            targetFound = true;
        }

        std::wstring imageName = UnicodeStringToWstring(&pSpi->ImageName);
        if (imageName.empty()) {
            if (currentPidUlong == 0) imageName = L"[System Idle Process]";
            else if (currentPidUlong == 4) imageName = L"System";
            else imageName = L"[Unknown]";
        }

        std::wcout << std::left << std::setw(10) << currentPidUlong
                   << std::setw(10) << HandleToULong(pSpi->InheritedFromUniqueProcessId)
                   << std::setw(8) << pSpi->SessionId
                   << std::setw(10) << pSpi->HandleCount
                   << std::setw(8) << pSpi->NumberOfThreads
                   << imageName << std::endl;

      
        if (currentPidUlong != 0 && currentPidUlong != 4) {
            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
            CLIENT_ID clientId = { currentPidHandle, NULL };
            status = NtOpenProcess(&hProcess, 
                                   PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE | THREAD_QUERY_INFORMATION, 
                                   &objAttr, 
                                   &clientId);

            if (NT_SUCCESS(status)) {
                AnalyzeProcessPEB(hProcess, currentPidHandle);
                AnalyzeProcessThreads(hProcess, pSpi);
                AnalyzeProcessMemory(hProcess, currentPidHandle);
                AnalyzeProcessHandles(hProcess, currentPidHandle); // Feature 4
                NtClose(hProcess);
            } else {
                 std::wcerr << L"  [WARN] Could not open process " << currentPidUlong << L". Status: 0x" << std::hex << status << std::dec << std::endl;
            }
        }
        std::wcout << std::wstring(80, L'-') << std::endl; 

        if (pSpi->NextEntryOffset == 0) break;
        pSpi = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pSpi + pSpi->NextEntryOffset);
    }

    if (targetPid != 0 && !targetFound) {
        std::wcerr << L"[WARN] Target PID " << targetPid << L" not found or could not be analyzed." << std::endl;
    }
}


PPEB GetProcessPEB(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (NT_SUCCESS(status) && returnLength == sizeof(pbi)) return pbi.PebBaseAddress;
    return nullptr;
}

PTEB GetThreadTEB(HANDLE hThread) {
    THREAD_BASIC_INFORMATION tbi;
    ULONG returnLength = 0;
    NTSTATUS status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), &returnLength);
    if (NT_SUCCESS(status) && returnLength == sizeof(tbi)) return (PTEB)tbi.TebBaseAddress;
    return nullptr;
}


NTSTATUS ReadProcessMemoryNative(HANDLE hProcess, PVOID baseAddress, PVOID buffer, SIZE_T size, PSIZE_T bytesRead) {
    return NtReadVirtualMemory(hProcess, baseAddress, buffer, size, bytesRead);
}


void AnalyzeProcessPEB(HANDLE hProcess, HANDLE processId) {
    PPEB pebAddress = GetProcessPEB(hProcess);
    if (!pebAddress) return;
    PEB peb;
    SIZE_T bytesRead = 0;
    NTSTATUS status = ReadProcessMemoryNative(hProcess, pebAddress, &peb, sizeof(PEB), &bytesRead);
    if (!NT_SUCCESS(status) || bytesRead != sizeof(PEB)) return;
    std::wcout << L"  PEB Address: 0x" << std::hex << (ULONG_PTR)pebAddress << std::dec << std::endl;
    if (peb.ProcessParameters) {
        RTL_USER_PROCESS_PARAMETERS params;
        status = ReadProcessMemoryNative(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead);
        if (NT_SUCCESS(status) && bytesRead == sizeof(params)) {
            if (params.CommandLine.Length > 0 && params.CommandLine.Buffer) {
                std::vector<WCHAR> cmdLineBuffer(params.CommandLine.Length / sizeof(WCHAR) + 1, 0);
                status = ReadProcessMemoryNative(hProcess, params.CommandLine.Buffer, cmdLineBuffer.data(), params.CommandLine.Length, &bytesRead);
                if (NT_SUCCESS(status)) std::wcout << L"    Command Line: " << cmdLineBuffer.data() << std::endl;
            }
            if (params.ImagePathName.Length > 0 && params.ImagePathName.Buffer) {
                 std::vector<WCHAR> imgPathBuffer(params.ImagePathName.Length / sizeof(WCHAR) + 1, 0);
                 status = ReadProcessMemoryNative(hProcess, params.ImagePathName.Buffer, imgPathBuffer.data(), params.ImagePathName.Length, &bytesRead);
                 if (NT_SUCCESS(status)) std::wcout << L"    Image Path:   " << imgPathBuffer.data() << std::endl;
            }
        }
    }
    if (peb.Ldr) {
        PEB_LDR_DATA ldrData;
        status = ReadProcessMemoryNative(hProcess, peb.Ldr, &ldrData, sizeof(ldrData), &bytesRead);
        if (NT_SUCCESS(status) && bytesRead == sizeof(ldrData)) {
            std::wcout << L"    Loaded Modules (InLoadOrder):" << std::endl;
            LIST_ENTRY* head = (LIST_ENTRY*)((ULONG_PTR)peb.Ldr + offsetof(PEB_LDR_DATA, InLoadOrderModuleList)); 
            LIST_ENTRY currentEntryData;
            LIST_ENTRY* currentEntryPtr = ldrData.InLoadOrderModuleList.Flink;
            status = ReadProcessMemoryNative(hProcess, currentEntryPtr, &currentEntryData, sizeof(LIST_ENTRY), &bytesRead);
            while (NT_SUCCESS(status) && currentEntryPtr != head) {
                ULONG_PTR entryAddress = (ULONG_PTR)currentEntryPtr - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                LDR_DATA_TABLE_ENTRY moduleEntry;
                status = ReadProcessMemoryNative(hProcess, (PVOID)entryAddress, &moduleEntry, sizeof(moduleEntry), &bytesRead);
                if (NT_SUCCESS(status) && bytesRead == sizeof(moduleEntry)) {
                    if (moduleEntry.BaseDllName.Length > 0 && moduleEntry.BaseDllName.Buffer) {
                        std::vector<WCHAR> dllNameBuffer(moduleEntry.BaseDllName.Length / sizeof(WCHAR) + 1, 0);
                        NTSTATUS nameStatus = ReadProcessMemoryNative(hProcess, moduleEntry.BaseDllName.Buffer, dllNameBuffer.data(), moduleEntry.BaseDllName.Length, &bytesRead);
                        if (NT_SUCCESS(nameStatus)) {
                             std::wcout << L"      0x" << std::hex << std::setw(16) << std::setfill(L'0') << (ULONG_PTR)moduleEntry.DllBase 
                                        << L"  " << dllNameBuffer.data() << std::dec << std::setfill(L' ') << std::endl;
                        }
                    }
                } else { break; }
                currentEntryPtr = moduleEntry.InLoadOrderLinks.Flink; 
                status = ReadProcessMemoryNative(hProcess, currentEntryPtr, &currentEntryData, sizeof(LIST_ENTRY), &bytesRead);
            }
        }
    }
}


void AnalyzeProcessThreads(HANDLE hProcess, PSYSTEM_PROCESS_INFORMATION pSpi) {
    std::wcout << L"  Threads (" << pSpi->NumberOfThreads << L") :" << std::endl;
    PSYSTEM_THREAD_INFORMATION pThreadInfo = pSpi->Threads;
    for (ULONG i = 0; i < pSpi->NumberOfThreads; ++i) {
        HANDLE hThread = nullptr;
        PTEB tebAddress = nullptr;
        HANDLE currentTid = pThreadInfo[i].ClientId.UniqueThread;
        ULONG tidUlong = HandleToULong(currentTid);
        std::wcout << L"    TID: " << std::setw(10) << tidUlong;
        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
        CLIENT_ID threadClientId = { pSpi->UniqueProcessId, currentTid }; 
        NTSTATUS status = NtOpenThread(&hThread, THREAD_QUERY_INFORMATION, &objAttr, &threadClientId);
        if (NT_SUCCESS(status)) {
            tebAddress = GetThreadTEB(hThread);
            if (tebAddress) {
                std::wcout << L" TEB: 0x" << std::hex << (ULONG_PTR)tebAddress << std::dec;
                TEB teb;
                SIZE_T bytesRead = 0;
                status = ReadProcessMemoryNative(hProcess, tebAddress, &teb, sizeof(TEB), &bytesRead);
                if (NT_SUCCESS(status) && bytesRead == sizeof(TEB)) {
                    std::wcout << L" StackBase: 0x" << std::hex << (ULONG_PTR)teb.NtTib.StackBase 
                               << L" StackLimit: 0x" << (ULONG_PTR)teb.NtTib.StackLimit << std::dec;
                } else { std::wcout << L" (Failed to read TEB)"; }
            } else { std::wcout << L" (Failed to get TEB address)"; }
            NtClose(hThread);
        } else { std::wcout << L" (Failed to open thread handle)"; }
        std::wcout << L" StartAddr: 0x" << std::hex << (ULONG_PTR)pThreadInfo[i].StartAddress << std::dec
                   << L" State: " << pThreadInfo[i].ThreadState 
                   << L" WaitReason: " << pThreadInfo[i].WaitReason << std::endl;
    }
}


void AnalyzeProcessMemory(HANDLE hProcess, HANDLE processId) {
    std::wcout << L"  Memory Regions:" << std::endl;
    std::wcout << L"    " << std::left << std::setw(18) << L"BaseAddress" 
              << std::setw(18) << L"EndAddress" 
              << std::setw(12) << L"Size (KB)" 
              << std::setw(10) << L"State" 
              << std::setw(10) << L"Type" 
              << std::setw(10) << L"Protect" 
              << L"Anomalies" << std::endl;
    std::wcout << L"    " << std::wstring(80, L'-') << std::endl;
    MEMORY_BASIC_INFORMATION mbi;
    PVOID currentAddress = nullptr;
    NTSTATUS status;
    while (true) {
        status = NtQueryVirtualMemory(hProcess, currentAddress, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);
        if (!NT_SUCCESS(status) || mbi.BaseAddress == nullptr) {
            if (status == STATUS_INVALID_PARAMETER || status == STATUS_ACCESS_DENIED) break; 
            break; 
        }
        PVOID endAddress = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        SIZE_T regionSizeKB = mbi.RegionSize / 1024;
        if (mbi.State == MEM_COMMIT) {
            std::string protectionStr = ProtectionToString(mbi.Protect);
            std::string typeStr = MemoryTypeToString(mbi.Type);
            std::string stateStr = MemoryStateToString(mbi.State);
            std::string anomalies = "";
            if ((mbi.Protect & PAGE_EXECUTE_READWRITE) && mbi.Type == MEM_PRIVATE) anomalies += "[RWX_Private] ";
            if ((mbi.Protect & PAGE_EXECUTE_WRITECOPY) && mbi.Type == MEM_PRIVATE) anomalies += "[WCX_Private] ";
            if ((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) && mbi.Type != MEM_IMAGE) anomalies += "[Executable_NotImage] ";
            std::wcout << L"    0x" << std::hex << std::setw(16) << std::setfill(L'0') << (ULONG_PTR)mbi.BaseAddress
                       << L" 0x" << std::setw(16) << (ULONG_PTR)endAddress << std::dec << std::setfill(L' ')
                       << std::setw(12) << regionSizeKB
                       << std::setw(10) << stateStr.c_str()
                       << std::setw(10) << typeStr.c_str()
                       << std::setw(10) << protectionStr.c_str()
                       << anomalies.c_str() << std::endl;
        }
        currentAddress = endAddress;
        if (mbi.RegionSize == 0) break; 
    }
}


void AnalyzeProcessHandles(HANDLE hProcess, HANDLE processId) {
    NTSTATUS status;
    ULONG bufferSize = 1024 * 1024; // Start with 1MB buffer
    std::unique_ptr<BYTE[]> buffer;
    ULONG returnLength;
    ULONG pidUlong = HandleToULong(processId);

    std::wcout << L"  Handles:" << std::endl;

    while (true) {
        buffer = std::make_unique<BYTE[]>(bufferSize);
        status = NtQuerySystemInformation(SystemHandleInformation, buffer.get(), bufferSize, &returnLength);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize = returnLength + 8192; 
        } else if (!NT_SUCCESS(status)) {
            std::wcerr << L"    [WARN] NtQuerySystemInformation(SystemHandleInformation) failed. Status: 0x" << std::hex << status << std::dec << std::endl;
            return;
        } else { break; }
    }

    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer.get();
    std::wcout << L"    " << std::left << std::setw(10) << L"Handle" 
              << std::setw(10) << L"TypeIndex" 
              << std::setw(20) << L"TypeName" 
              << L"ObjectName" << std::endl;
     std::wcout << L"    " << std::wstring(80, L'-') << std::endl;

    for (ULONG i = 0; i < handleInfo->NumberOfHandles; ++i) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleInfo->Handles[i];
        if (handle.UniqueProcessId == pidUlong) {
            std::wstring typeName = GetHandleTypeName(hProcess, (HANDLE)handle.HandleValue, handle.ObjectTypeIndex);
            std::wstring objectName = GetHandleObjectName(hProcess, (HANDLE)handle.HandleValue);
            std::wcout << L"    0x" << std::hex << std::setw(8) << std::setfill(L'0') << handle.HandleValue << std::dec << std::setfill(L' ')
                       << std::setw(10) << handle.ObjectTypeIndex
                       << std::setw(20) << typeName
                       << objectName << std::endl;
            
        }
    }
}


std::wstring GetHandleTypeName(HANDLE hProcess, HANDLE handle, USHORT typeIndex) {
    auto it = handleTypeMap.find(typeIndex);
    if (it != handleTypeMap.end()) return it->second;
    HANDLE duplicatedHandle = nullptr;
    NTSTATUS status = NtDuplicateObject(hProcess, handle, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
    if (!NT_SUCCESS(status)) return L"(Dup Failed)";
    ULONG bufferSize = 1024;
    auto typeInfoBuffer = std::make_unique<BYTE[]>(bufferSize);
    POBJECT_TYPE_INFORMATION typeInfo = (POBJECT_TYPE_INFORMATION)typeInfoBuffer.get();
    status = NtQueryObject(duplicatedHandle, ObjectTypeInformation, typeInfo, bufferSize, &bufferSize);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        typeInfoBuffer = std::make_unique<BYTE[]>(bufferSize);
        typeInfo = (POBJECT_TYPE_INFORMATION)typeInfoBuffer.get();
        status = NtQueryObject(duplicatedHandle, ObjectTypeInformation, typeInfo, bufferSize, &bufferSize);
    }
    std::wstring typeName = L"(Query Failed)";
    if (NT_SUCCESS(status)) {
        typeName = UnicodeStringToWstring(&typeInfo->TypeName);
        handleTypeMap[typeIndex] = typeName;
    }
    NtClose(duplicatedHandle);
    return typeName;
}


std::wstring GetHandleObjectName(HANDLE hProcess, HANDLE handle) {
    HANDLE duplicatedHandle = nullptr;
    NTSTATUS status = NtDuplicateObject(hProcess, handle, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES);
    if (!NT_SUCCESS(status)) return L"(Dup Failed)";
    ULONG bufferSize = 2048;
    auto nameInfoBuffer = std::make_unique<BYTE[]>(bufferSize);
    POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)nameInfoBuffer.get();
    status = NtQueryObject(duplicatedHandle, ObjectNameInformation, nameInfo, bufferSize, &bufferSize);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        nameInfoBuffer = std::make_unique<BYTE[]>(bufferSize);
        nameInfo = (POBJECT_NAME_INFORMATION)nameInfoBuffer.get();
        status = NtQueryObject(duplicatedHandle, ObjectNameInformation, nameInfo, bufferSize, &bufferSize);
    }
    std::wstring objectName = L"";
    if (NT_SUCCESS(status) && nameInfo->Name.Length > 0) {
        objectName = UnicodeStringToWstring(&nameInfo->Name);
    } else if (status == STATUS_BUFFER_OVERFLOW) {
         objectName = L"(Name Too Long)";
    } else if (status != STATUS_SUCCESS && status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_OVERFLOW && status != STATUS_INVALID_INFO_CLASS) {
        
    }
    NtClose(duplicatedHandle);
    return objectName;
}


