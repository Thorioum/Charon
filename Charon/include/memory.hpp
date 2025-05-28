#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <unordered_map>

namespace MemExternal {
	std::pair<HANDLE, ULONG> WaitForProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, std::string procName);
	ULONG getProcId(std::string name);
	bool handleIsStillValid(HANDLE handle);

	ULONGLONG readJmp32Rel(HANDLE handle, ULONGLONG instructionAddr);
	ULONGLONG readJmpAbs(HANDLE handle, ULONGLONG instructionAddr);
	ULONGLONG writeJmpAbs(HANDLE handle, ULONGLONG instructionAddr, ULONGLONG targetAddr);

	std::unordered_map<std::string, ULONG> getExportsFunctions(HANDLE handle, HMODULE module);
	HMODULE getLoadedModule(HANDLE handle, const char* modName);
	ULONG getModuleSize(HANDLE handle, HMODULE module);

	//for testing
	void suspendAllThreads(HANDLE handle);
	void resumeAllThreads(HANDLE handle);
	void suspendByfronThreads(HANDLE handle);
	void resumeByfronThreads(HANDLE handle);

	std::vector<ULONG> GetThreadIds(ULONG processId);
	ULONGLONG getThreadStartAddr(HANDLE threadHandle);
}

namespace MemInternal {

	void __forceinline adjustRelocations(ULONGLONG dll) {
        #define RELOC_FLAG(info) (((info) >> 12) == IMAGE_REL_BASED_DIR64)

        auto* dosHeader = (IMAGE_DOS_HEADER*)(dll);
        auto* ntHeaders = (IMAGE_NT_HEADERS*)(dll + dosHeader->e_lfanew);
        auto* optionalHeader = &ntHeaders->OptionalHeader;
        ULONGLONG locationDelta = dll - optionalHeader->ImageBase;

        if (locationDelta) {
            auto& relocDir = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (relocDir.Size) {
                auto* pRelocData = (IMAGE_BASE_RELOCATION*)(dll + relocDir.VirtualAddress);
                const auto* pRelocEnd = (IMAGE_BASE_RELOCATION*)((ULONGLONG)(pRelocData)+relocDir.Size);

                while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
                    UINT entryCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    WORD* relocs = (WORD*)(pRelocData + 1);

                    for (UINT i = 0; i < entryCount; ++i, ++relocs) {
                        if (RELOC_FLAG(*relocs)) {
                            ULONGLONG* patch = (ULONGLONG*)(dll + pRelocData->VirtualAddress + ((*relocs) & 0xFFF));
                            *patch += locationDelta;
                        }
                    }
                    pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)(pRelocData)+pRelocData->SizeOfBlock);
                }
            }
        }
    }

	void __forceinline fixImports(ULONGLONG dll, 
		decltype(&LoadLibraryA) &pLoadLibraryA, 
		decltype(&GetModuleHandleA) &pGetModuleHandleA, 
		decltype(&GetProcAddress) &pGetProcAddress ) {
        auto* dosHeader = (IMAGE_DOS_HEADER*)(dll);
        auto* ntHeaders = (IMAGE_NT_HEADERS*)(dll + dosHeader->e_lfanew);
        auto* optionalHeader = &ntHeaders->OptionalHeader;
        auto size = optionalHeader->SizeOfImage;

        auto& importDir = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size) {
            auto* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(dll + importDir.VirtualAddress);
            while (importDesc->Name) {
                char* moduleName = (char*)(dll + importDesc->Name);
                HMODULE module = pGetModuleHandleA(moduleName);
                if (!module) module = pLoadLibraryA(moduleName);
                if (!module) {
                    importDesc++;
                    continue;
                }

                auto* moduleDosHeader = (IMAGE_DOS_HEADER*)(module);
                auto* moduleNtHeaders = (IMAGE_NT_HEADERS*)((ULONGLONG)module + moduleDosHeader->e_lfanew);
                auto SizeOfImage = moduleNtHeaders->OptionalHeader.SizeOfImage;

                ULONGLONG* thunk = (ULONGLONG*)(dll + importDesc->OriginalFirstThunk);
                ULONGLONG* func = (ULONGLONG*)(dll + importDesc->FirstThunk);
                if (!thunk) thunk = func;

                while (*thunk) {
                    if (IMAGE_SNAP_BY_ORDINAL(*thunk)) {
                        *func = (ULONGLONG)pGetProcAddress(module, (char*)(*thunk & 0xFFFF));
                    }
                    else {
                        auto* Import = (IMAGE_IMPORT_BY_NAME*)(dll + *thunk);
                        *func = (ULONGLONG)pGetProcAddress(module, Import->Name);
                    }
                    thunk++;
                    func++;
                }
                importDesc++;
            }
        }
    }

}
