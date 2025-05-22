#include "../include/manualmapper.hpp"
#include "../include/util.hpp"
#include "../include/globals.hpp"
#include <spdlog/spdlog.h>
#include <iostream>

using NtQuerySystemInformation_t = int32_t(__stdcall*)(int32_t SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

SCF_WRAP_START;
int32_t __stdcall NtQuerySystemInformation(
	int32_t SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
) {
	SCF_START;

	//get stack
	auto Original = reinterpret_cast<NtQuerySystemInformation_t>(Stack[1]);
	return Original(SystemInformationClass,SystemInformation,SystemInformationLength,ReturnLength);

	SCF_END;
}
SCF_WRAP_END;

void myFunctionEnd() {}

void ManualMapper::inject(HANDLE handle, const std::string& dllPath) {

	HMODULE dllBase = /*_allocDll(handle, dllPath)*/(HMODULE)1;
	if (dllBase) {
		spdlog::info("Successfully allocated dll in target process.");
		ULONGLONG statusAddr = _createStatus(handle);

		HMODULE ntdll = MemExternal::getLoadedModule(handle, "ntdll.dll");
		ULONGLONG functionAddr = (ULONGLONG)ntdll + MemExternal::getExportsFunctions(handle, ntdll)["NtQuerySystemInformation"];

		ULONGLONG stub = MemExternal::readJmp32Rel(handle, functionAddr);

		//dont even ask. (ULONGLONG)NtQuerySystemInformation for some reason is a jmp instruction pointing to the actual code, so i read it here
		ULONGLONG aNtQuerySystemInformation = MemExternal::readJmp32Rel(GetCurrentProcess(), (ULONGLONG)NtQuerySystemInformation);

		ULONGLONG detourPage = _createDetour(handle, (NtQuerySystemInformation_t)aNtQuerySystemInformation, (ULONGLONG)dllBase, stub, functionAddr);
		FlushInstructionCache(handle, (LPVOID)stub, 16);
	}

}

HMODULE ManualMapper::_allocDll(HANDLE handle, const std::string& dllPath) {
	
	std::vector<UCHAR> dllByteVec = Util::readFile(dllPath);
	UCHAR* dllBytes = dllByteVec.data();

	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(dllBytes);
	IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(dllBytes + dosHeader->e_lfanew);

	IMAGE_OPTIONAL_HEADER* optHeader = &ntHeaders->OptionalHeader;
	IMAGE_FILE_HEADER* fileHeader = &ntHeaders->FileHeader;

	//put bytes into roblox
	LPVOID allocBase = VirtualAllocEx(handle, 0, optHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT,  PAGE_EXECUTE_READWRITE);
	if (!allocBase) {
		spdlog::error("Failed to allocate memory for dll in target process. Err: {}", GetLastError());
		return 0;
	}
	if (!WriteProcessMemory(handle, allocBase, dllBytes, 4096, 0)) {
		spdlog::error("Failed to write memory of dll in alloc in target process. Err: {}", GetLastError());
		return 0;
	}
	
	//initialize each section (.text, .data) correctly to its virtual address, offsets wont match in file, this is why its needed.
	IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (uint32_t i = 0; i != fileHeader->NumberOfSections; ++i, ++SectionHeader) {
		if (SectionHeader->SizeOfRawData) {
			WriteProcessMemory(handle, (LPVOID)((BYTE*)allocBase + SectionHeader->VirtualAddress), dllBytes + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData,0);
		}
	}

	return (HMODULE)allocBase;
}

ULONGLONG ManualMapper::_calculateLocalFuncSize(ULONGLONG funcBase)
{
	ULONG size = 0;
	while (*(ULONG*)(funcBase+size) != SCF_END_MARKER) {
		size++;
	}
	const size_t kSize = size;

	while (size - kSize < 16) {
		switch (*(UCHAR*)(funcBase + size)) {
		case 0xCC: {
			if (size == kSize + 3) {
				goto return_size;
			}
			break;
		}
		case 0xC2: {
			size += 3;
			goto return_size;
		}
		case 0xC3: {
			size++;
			goto return_size;
		}
		}

		size++;
	}
	return_size:
		return size;
	
}

ULONGLONG ManualMapper::_createStatus(HANDLE handle)
{
	LPVOID allocBase = VirtualAllocEx(handle, 0, sizeof(Status), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!allocBase) {
		spdlog::error("Failed to allocate memory for status in target process. Err: {}", GetLastError());
		return 0;
	}

	Status newStatus = STATUS_BUSY;
	if (!WriteProcessMemory(handle, allocBase, &newStatus, sizeof(Status), 0)) {
		spdlog::error("Failed to write start status in target process. Err: {}", GetLastError());
		return 0;
	}
}
