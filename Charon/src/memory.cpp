#include "../include/memory.hpp"
#include "../include/def.hpp"
#include <spdlog/spdlog.h>
#include <TlHelp32.h>
#include <memory>
#include <Psapi.h>
#include <iostream>
#include <tchar.h>
#include <ranges>

typedef ULONG(WINAPI* NtQueryInformationThread_t)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );
struct HandleDisposer {
    using pointer = HANDLE;
    void operator()(HANDLE handle) const {
        if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};
using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;

std::pair<HANDLE, ULONG> MemExternal::WaitForProcess(ULONG dwDesiredAccess, BOOL bInheritHandle, std::string procName)
{
    ULONG procId = NULL;
    while (!procId) {
        procId = getProcId(procName);
        if (procId) break;
        Sleep(10);
    }
    HANDLE handle = OpenProcess(dwDesiredAccess, bInheritHandle, procId);
    if (handle == INVALID_HANDLE_VALUE || !handle) {
        spdlog::error("Error getting handle for process: {}", procName);
        return { NULL, NULL };
    }
    else {
        spdlog::info("Opened handle to {} with PID: {}", procName, procId);
        return { handle, procId };
    }
}

bool MemExternal::handleIsStillValid(HANDLE handle) {
    ULONG procId = NULL;
    procId = GetProcessId(handle);
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procId);
    if (process == NULL) {
        return false;
    }
    ULONG exitCode;
    if (GetExitCodeProcess(process, &exitCode)) {
        CloseHandle(process);
        return (exitCode == STILL_ACTIVE);
    }
    CloseHandle(process);
    return true;
}

ULONGLONG MemExternal::readJmp32Rel(HANDLE handle, ULONGLONG instructionAddr) {
    //not unsigned, as can also be negative
    LONG rva;
    if (!ReadProcessMemory(handle, (LPVOID)(instructionAddr + 1), &rva, sizeof(rva), 0)) {
		spdlog::error("Failed to read jmp32 rel! Err: {}", GetLastError());
		return rva;
    }
    return ((instructionAddr + 5) + rva);
}

ULONGLONG MemExternal::readJmpAbs(HANDLE handle, ULONGLONG instructionAddr) {
    ULONGLONG addr = 0;
    if (!ReadProcessMemory(handle, (LPVOID)(instructionAddr + 6), &addr, sizeof(addr), 0)) {
		spdlog::error("Failed to read jmp rip! Err: {}", GetLastError());
        return addr;
    }
    return addr;
}

ULONGLONG MemExternal::writeJmpAbs(HANDLE handle, ULONGLONG instructionAddr, ULONGLONG targetAddr) {
    ULONGLONG oldAddr = readJmpAbs(handle, instructionAddr);

    ULONG oldProt;
    ULONG temp;

    if (!VirtualProtectEx(handle, (LPVOID)(instructionAddr + 6), sizeof(targetAddr), PAGE_EXECUTE_READWRITE, &oldProt)) {
		spdlog::error("Failed to change memory protection! Err: {}", GetLastError());
    }
    if (!WriteProcessMemory(handle, (LPVOID)(instructionAddr + 6), &targetAddr, sizeof(targetAddr), 0)) {
        spdlog::error("Failed to overwrite jmp rip! Err: {}", GetLastError());
        return 0;
    }
    
	VirtualProtectEx(handle, (LPVOID)(instructionAddr + 6), sizeof(targetAddr), oldProt, &temp);

    return oldAddr;
}

std::unordered_map<std::string, ULONG> MemExternal::getExportsFunctions(HANDLE handle, HMODULE module) {

    std::unordered_map< std::string, ULONG> exportMap = std::unordered_map< std::string, ULONG>();

    //read modules dos header
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(handle, module, (LPVOID)&dosHeader, sizeof(dosHeader), 0)) {
        spdlog::error("Failed to read DOS header: {}", GetLastError());
        return exportMap;
    }

    //read the ntHeader using the offset provided in the dosHeader
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(handle, (BYTE*)module + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), 0)) {
        spdlog::error("Failed to read NT headers: {}", GetLastError());
        return exportMap;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        spdlog::error("Invalid NT header signature!");
        return exportMap;
    }

    // get export directory RVA and size
    ULONG exportDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG exportDirSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (exportDirRVA == 0) {
        spdlog::error("No export directory found");
        return exportMap;
    }

    // read export directory
    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadProcessMemory(handle, (BYTE*)module + exportDirRVA, &exportDir, sizeof(exportDir), 0)) {
        spdlog::error("Failed to read export directory: {}", GetLastError());
        CloseHandle(handle);
        return exportMap;
    }

    if (exportDirSize == 0) {
        spdlog::error("No functions found in export directory");
        return exportMap;
    }
    //
    // Read function address table
    std::vector<ULONG> functions(exportDir.NumberOfFunctions);
    if (!ReadProcessMemory(handle,
        (BYTE*)module + exportDir.AddressOfFunctions,
        functions.data(),
        exportDir.NumberOfFunctions * sizeof(ULONG), 0)) {
        spdlog::error("Failed to read functions addresses: ", GetLastError());
        return exportMap;
    }

    // Read name pointer table
    std::vector<ULONG> names(exportDir.NumberOfNames);
    if (!ReadProcessMemory(handle,
        (BYTE*)module + exportDir.AddressOfNames,
        names.data(),
        exportDir.NumberOfNames * sizeof(ULONG), 0)) {
        spdlog::error("Failed to read name pointers: ", GetLastError());
        return exportMap;
    }

    // Read ordinal table
    std::vector<WORD> ordinals(exportDir.NumberOfNames);
    if (!ReadProcessMemory(handle,
        (BYTE*)module + exportDir.AddressOfNameOrdinals,
        ordinals.data(),
        exportDir.NumberOfNames * sizeof(WORD), 0)) {
        spdlog::error("Failed to read ordinals: {}", GetLastError());
        return exportMap;
    }
    //
    // enumerate exports

    // get section headers
    std::vector<IMAGE_SECTION_HEADER> sections(ntHeaders.FileHeader.NumberOfSections);
    if (!ReadProcessMemory(handle,
        (BYTE*)module + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS),
        sections.data(),
        sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections,
        nullptr)) {
        spdlog::error("Failed to read section headers: {}", GetLastError());
        return exportMap;
    }

    // find executable sections
    std::vector<ULONG> executableRanges;
    for (const auto& section : sections) {
        if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            executableRanges.push_back(section.VirtualAddress);
            executableRanges.push_back(section.VirtualAddress + section.Misc.VirtualSize);
        }
    }

    for (ULONG i = 0; i < exportDir.NumberOfNames; i++) {

        // read function name
        char functionName[256] = { 0 };
        if (!ReadProcessMemory(handle,
            (BYTE*)module + names[i],
            functionName,
            sizeof(functionName) - 1, 0)) {
            spdlog::error("Failed to read function name at index {}", i);
            continue;
        }

        // get function RVA
        ULONG functionRVA = functions[ordinals[i]];
        if (functionRVA == 0) continue;

        bool isExecutable = false;
        for (size_t j = 0; j < executableRanges.size(); j += 2) {
            if (functionRVA >= executableRanges[j] && functionRVA < executableRanges[j + 1]) {
                isExecutable = true;
                break;
            }
        }

        if (isExecutable) {
            exportMap[functionName] = functionRVA;
        }
    }

    return exportMap;
}

HMODULE MemExternal::getLoadedModule(HANDLE handle, const char* modName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(handle));
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!strcmp(modEntry.szModule, modName))
                {
                    return (HMODULE)modEntry.modBaseAddr;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return NULL;
}
ULONG MemExternal::getModuleSize(HANDLE handle, HMODULE module)
{
    MODULEINFO moduleInfo;
    if (GetModuleInformation(handle, module, &moduleInfo, sizeof(moduleInfo)))
    {
        return moduleInfo.SizeOfImage;
    }
    return 0;
}
std::vector<ULONG> MemExternal::GetThreadIds(ULONG processId) {
    std::vector<ULONG> threadIds;
    HANDLE threadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (threadSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(threadSnap, &te32)) {
            do {
                if (te32.th32OwnerProcessID == processId) {
                    threadIds.push_back(te32.th32ThreadID);
                }
            } while (Thread32Next(threadSnap, &te32));
        }
        CloseHandle(threadSnap);
    }
    return threadIds;
}

ULONGLONG MemExternal::getThreadStartAddr(HANDLE threadHandle)
{
    if (threadHandle == NULL || threadHandle == INVALID_HANDLE_VALUE) {
        return 0;
    }

    HMODULE hNtDll = LoadLibraryA("ntdll.dll");
    if (!hNtDll) {
        std::cerr << "Failed to load ntdll.dll. Error: " << GetLastError() << std::endl;
        return 0;
    }

    NtQueryInformationThread_t pNtQueryInformationThread =
        (NtQueryInformationThread_t)GetProcAddress(hNtDll, "NtQueryInformationThread");
    if (!pNtQueryInformationThread) {
        std::cerr << "Failed to get NtQueryInformationThread. Error: " << GetLastError() << std::endl;
        FreeLibrary(hNtDll);
        return 0;
    }

    ULONG_PTR startAddress = 0;
    ULONG status = pNtQueryInformationThread(
        threadHandle,
        ThreadQuerySetWin32StartAddress,
        &startAddress,
        sizeof(PVOID),
        nullptr
    );

    FreeLibrary(hNtDll);

    if (status != 0) {
        std::cerr << "NtQueryInformationThread failed. NTSTATUS: " << std::hex << status << std::endl;
        return 0;
    }

    return startAddress;
}
void MemExternal::suspendAllThreads(HANDLE handle) {
    DWORD processId = GetProcessId(handle);
    if (processId == 0) {
        return;
    }

    std::vector<DWORD> threadIds = GetThreadIds(processId);

    for (DWORD threadId : threadIds) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
        if (hThread != NULL) {
            if (SuspendThread(hThread) == (DWORD)-1);
            CloseHandle(hThread);
        }
    }
    return;
}
void MemExternal::resumeAllThreads(HANDLE handle)
{
    DWORD processId = GetProcessId(handle);
    if (processId == 0) {
        return;
    }

    std::vector<DWORD> threadIds = GetThreadIds(processId);

    for (DWORD threadId : threadIds | std::views::reverse) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (hThread != NULL) {
            if (ResumeThread(hThread) == (DWORD)-1);
            CloseHandle(hThread);
        }
    }
    return;
}

void MemExternal::suspendByfronThreads(HANDLE handle)
{
    DWORD processId = GetProcessId(handle);
    if (processId == 0) {
        return;
    }

    std::vector<DWORD> threadIds = GetThreadIds(processId);

    HMODULE byfron = MemExternal::getLoadedModule(handle, "RobloxPlayerBeta.dll");
    ULONGLONG byfronSize = MemExternal::getModuleSize(handle, byfron);

    for (DWORD threadId : threadIds) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
        if (hThread != NULL) {
            ULONG_PTR start = getThreadStartAddr(hThread);
            if (start > (ULONGLONG)byfron && start < (ULONGLONG)byfron + byfronSize) {
                if (SuspendThread(hThread) == (DWORD)-1);
                CloseHandle(hThread);
            }
        }
    }
    return;
}
void MemExternal::resumeByfronThreads(HANDLE handle)
{
    DWORD processId = GetProcessId(handle);
    if (processId == 0) {
        return;
    }

    std::vector<DWORD> threadIds = GetThreadIds(processId);

    HMODULE byfron = MemExternal::getLoadedModule(handle, "RobloxPlayerBeta.dll");
    ULONGLONG byfronSize = MemExternal::getModuleSize(handle, byfron);

    for (DWORD threadId : threadIds) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
        if (hThread != NULL) {
            ULONG_PTR start = getThreadStartAddr(hThread);
            if (start > (ULONGLONG)byfron && start < (ULONGLONG)byfron + byfronSize) {
                if (ResumeThread(hThread) == (DWORD)-1);
                CloseHandle(hThread);
            }
        }
    }
    return;
}

ULONG MemExternal::getProcId(std::string name) {
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(MODULEENTRY32);

    const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));

    if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
        return NULL;

    int highestCount = 0;
    ULONG procId = NULL;
    do {
        if (!name.compare(procEntry.szExeFile) && procEntry.cntThreads > highestCount) {
            highestCount = procEntry.cntThreads;
            procId = procEntry.th32ProcessID;
        }
    } while (Process32Next(snapshot_handle.get(), &procEntry));
    return procId;
}
