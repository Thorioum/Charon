#include "../include/manualmapper.hpp"
#include "../include/util.hpp"
#include "../include/globals.hpp"

#include <spdlog/spdlog.h>
#include <iostream>

SCF_WRAP_START;
void detour() {
	SCF_START;

	ULONGLONG dll = (ULONGLONG)(Stack[0]);
	auto status = (ULONG*)(Stack[1]);
	auto pLoadLibraryA = (decltype(&LoadLibraryA))(Stack[2]);
	auto pGetProcAddress = (decltype(&GetProcAddress))(Stack[3]);
	auto pGetModuleHandleA = (decltype(&GetModuleHandleA))(Stack[4]);

	auto* dosHeader = (IMAGE_DOS_HEADER*)(dll);
	auto* ntHeaders = (IMAGE_NT_HEADERS*)(dll + dosHeader->e_lfanew);
	auto* optionalHeader = &ntHeaders->OptionalHeader;

	ULONGLONG entryAddr = (ULONGLONG)dll + optionalHeader->AddressOfEntryPoint;
	*status = entryAddr;
	
	MemInternal::adjustRelocations(dll);

	MemInternal::fixImports(dll, pLoadLibraryA, pGetModuleHandleA, pGetProcAddress);

	*status = ManualMapper::STATUS_3;

	//call tls callbacks
	auto& tlsDataDir = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tlsDataDir.Size) {
		auto* tlsDir = (IMAGE_TLS_DIRECTORY*)(dll + tlsDataDir.VirtualAddress);
		if (tlsDir->AddressOfCallBacks) {
			auto* callbacks = (PIMAGE_TLS_CALLBACK*)(tlsDir->AddressOfCallBacks);
			while (*callbacks) {
				(*callbacks)((LPVOID)dll, DLL_PROCESS_ATTACH, nullptr);
				++callbacks;
			}
		}
	}

	*status = ManualMapper::STATUS_4;

	//call main function
	auto DllMain = (int(__stdcall*)(HMODULE, DWORD, void*))(entryAddr);
	DllMain((HMODULE)(dll), DLL_PROCESS_ATTACH, nullptr);

	SCF_END;
}
SCF_WRAP_END;

void ManualMapper::inject(HANDLE handle, const std::string& dllPath) {

	HMODULE dllBase = _allocDll(handle, dllPath);
	if (dllBase) {
		spdlog::info("Successfully allocated dll in target process.");

		HMODULE ntdll = MemExternal::getLoadedModule(handle, "ntdll.dll");
		ULONGLONG functionAddr = (ULONGLONG)ntdll + MemExternal::getExportsFunctions(handle, ntdll)["NtQuerySystemInformation"];

		ULONGLONG stub = MemExternal::readJmp32Rel(handle, functionAddr);

		ULONGLONG detourFunc;
		#ifdef _DEBUG //thanks debug mode very cool
			detourFunc = MemExternal::readJmp32Rel(GetCurrentProcess(), (ULONGLONG)detour);
		#else
			detourFunc = (ULONGLONG)detour;
		#endif

		ULONGLONG detourPage = _createDetour(handle, (void(__stdcall*)())detourFunc, (ULONGLONG)dllBase, stub, functionAddr);
	}

}

HMODULE ManualMapper::_allocDll(HANDLE handle, const std::string& dllPath) {
	
	std::vector<UCHAR> dllByteVec = Util::readFile(dllPath);
	UCHAR* dllBytes = dllByteVec.data();

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(dllBytes);
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(dllBytes + dosHeader->e_lfanew);

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
			goto return_size;
		}
		case 0xC3: {
			goto return_size;
		}
		}

		size++;
	}
	return_size:
		return size;
	
}

LPVOID ManualMapper::_createStatus(HANDLE handle)
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

	return allocBase;
}
