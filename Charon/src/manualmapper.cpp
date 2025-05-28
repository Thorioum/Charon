#include "../include/manualmapper.hpp"
#include "../include/util.hpp"
#include "../include/globals.hpp"
#include <spdlog/spdlog.h>
#include <iostream>

#define RELOC_FLAG(RelInfo) (((RelInfo) >> 12) == IMAGE_REL_BASED_DIR64)

SCF_WRAP_START;
void detour() {
	SCF_START;

	ULONGLONG dll = reinterpret_cast<ULONGLONG>(Stack[0]);
	auto status = reinterpret_cast<ULONG*>(Stack[1]);
	auto _LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(Stack[2]);
	auto _GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(Stack[3]);
	auto _GetModuleHandleA = reinterpret_cast<decltype(&GetModuleHandleA)>(Stack[4]);


	auto* Dos = reinterpret_cast<IMAGE_DOS_HEADER*>(dll);
	auto* Nt = reinterpret_cast<IMAGE_NT_HEADERS*>(dll + Dos->e_lfanew);
	auto* Opt = &Nt->OptionalHeader;
	auto Size = Opt->SizeOfImage;
	uintptr_t LocationDelta = dll - Opt->ImageBase;
	if (LocationDelta) {
		auto& RelocDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (RelocDir.Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(dll + RelocDir.VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + RelocDir.Size);

			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT EntryCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* Relocs = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i < EntryCount; ++i, ++Relocs) {
					if (RELOC_FLAG(*Relocs)) {
						UINT_PTR* Patch = reinterpret_cast<UINT_PTR*>(dll + pRelocData->VirtualAddress + ((*Relocs) & 0xFFF));
						*Patch += LocationDelta;
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	*status = ManualMapper::STATUS_2;
	ULONGLONG entryAddr = (ULONGLONG)dll + Opt->AddressOfEntryPoint;
	*status = entryAddr;

	auto& ImportDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (ImportDir.Size) {
		auto* ImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(dll + ImportDir.VirtualAddress);
		while (ImportDesc->Name) {
			char* ModName = reinterpret_cast<char*>(dll + ImportDesc->Name);
			HMODULE Mod = _GetModuleHandleA(ModName);
			if (!Mod) Mod = _LoadLibraryA(ModName);
			if (!Mod) { ++ImportDesc; continue; }

			auto* Dos = reinterpret_cast<IMAGE_DOS_HEADER*>(Mod);
			auto* Nt = reinterpret_cast<IMAGE_NT_HEADERS*>((uintptr_t)Mod + Dos->e_lfanew);
			auto SizeOfImage = Nt->OptionalHeader.SizeOfImage;

			uintptr_t* Thunk = reinterpret_cast<uintptr_t*>(dll + ImportDesc->OriginalFirstThunk);
			uintptr_t* Func = reinterpret_cast<uintptr_t*>(dll + ImportDesc->FirstThunk);
			if (!Thunk) Thunk = Func;

			while (*Thunk) {
				if (IMAGE_SNAP_BY_ORDINAL(*Thunk)) {
					*Func = (uintptr_t)_GetProcAddress(Mod, reinterpret_cast<char*>(*Thunk & 0xFFFF));
				}
				else {
					auto* Import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(dll + *Thunk);
					*Func = (uintptr_t)_GetProcAddress(Mod, Import->Name);
				}
				++Thunk; ++Func;
			}
			++ImportDesc;
		}
	}
	*status = ManualMapper::STATUS_3;

	auto& TlsDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (TlsDir.Size) {
		auto* Tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(dll + TlsDir.VirtualAddress);
		if (Tls->AddressOfCallBacks) {
			auto* Callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(Tls->AddressOfCallBacks);
			while (*Callbacks) {
				(*Callbacks)((LPVOID)dll, DLL_PROCESS_ATTACH, nullptr);
				++Callbacks;
			}
		}
	}
	*status = ManualMapper::STATUS_4;

	
	auto Entry = reinterpret_cast<int(__stdcall*)(HMODULE, DWORD, void*)>(entryAddr);
	Entry(reinterpret_cast<HMODULE>(dll), DLL_PROCESS_ATTACH, nullptr);

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

		//this is needed in debug mode for some reason..
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
