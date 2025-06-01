#include "../include/manualmapper.hpp"
#include "../include/util.hpp"
#include "../include/globals.hpp"
#include "../include/def.hpp"
#include <spdlog/spdlog.h>
#include <iostream>

#pragma optimize("", off);
void dllDetourFunc() {
	DEFINE_STACK;
	ULONGLONG dll = (ULONGLONG)(Stack[0]);
	ULONGLONG* status = (ULONGLONG*)(Stack[1]);
	auto pLoadLibraryA = (decltype(&LoadLibraryA))(Stack[2]);
	auto pGetProcAddress = (decltype(&GetProcAddress))(Stack[3]);
	auto pGetModuleHandleA = (decltype(&GetModuleHandleA))(Stack[4]);

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(dll);
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(dll + dosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER64* optionalHeader = &ntHeaders->OptionalHeader;
	ULONG size = optionalHeader->SizeOfImage;

	ULONGLONG entryAddr = (ULONGLONG)dll + optionalHeader->AddressOfEntryPoint;

	MemInternal::adjustRelocations(dll);
	MemInternal::fixImports(dll, pLoadLibraryA, pGetModuleHandleA, pGetProcAddress, status);
	
	*status = ManualMapper::STATUS_2;
	
	//call tls callbacks
	auto& tlsDataDir = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tlsDataDir.Size) {
		auto* tlsDir = (IMAGE_TLS_DIRECTORY*)(dll + tlsDataDir.VirtualAddress);
		if (tlsDir->AddressOfCallBacks) {
			auto* callbacks = (PIMAGE_TLS_CALLBACK*)(tlsDir->AddressOfCallBacks);
			while (*callbacks) {
				(*callbacks)((LPVOID)dll, DLL_PROCESS_ATTACH, nullptr);
				callbacks++;
			}
		}
	}

	*status = ManualMapper::STATUS_3;

	//call main!
	auto DllMain = reinterpret_cast<int(__stdcall*)(HMODULE, DWORD, void*)>(entryAddr);
	DllMain(reinterpret_cast<HMODULE>(dll), DLL_PROCESS_ATTACH, NULL);
	
	END_MARKER;
}
#pragma optimize("", on);


void ManualMapper::inject(HANDLE handle, const std::string& dllPath) {
	#ifdef _DEBUG //thanks debug mode very cool (lots of funky mechanics with local function reading in debug)
		spdlog::info("Dont build in debug mode. Thanks");
		return;
	#endif
	MemExternal::suspendByfronThreads(handle);

	Allocation dllBase = _allocDll(handle, dllPath);
	if (dllBase.base) {
		spdlog::info("Successfully allocated dll in target process.");

		HMODULE dllHookMod = MemExternal::getLoadedModule(handle, "KERNELBASE.dll");
		ULONGLONG dllHookFunctionAddr = (ULONGLONG)dllHookMod + MemExternal::getExportsFunctions(handle, dllHookMod)["GetCurrentProcessId"];
		ULONGLONG dllStub = MemExternal::readJmp32Rel(handle, dllHookFunctionAddr) - 14;

		Detour dllDetour = _createDllDetour(handle, (LPVOID)dllDetourFunc, dllStub, dllBase.base);


		//yes this is shit.
		//lack of cfg bypass makes this necessary
		//and no it doesnt really work well, it breaks sometimes
		while (true) {
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQueryEx(handle, (LPVOID)dllBase.base, &mbi, sizeof(mbi))) {
				ULONG oldProt;
				VirtualProtectEx(handle, mbi.AllocationBase, mbi.RegionSize, PAGE_EXECUTE_READ, &oldProt);
			}
		}
	}

	Sleep(3500);

	MemExternal::resumeByfronThreads(handle);

}

ManualMapper::Allocation ManualMapper::_allocDll(HANDLE handle, const std::string& dllPath) {
	
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
		return { 0,0 };
	}
	if (!WriteProcessMemory(handle, allocBase, dllBytes, 0x1000, 0)) {
		spdlog::error("Failed to write memory of dll in alloc in target process. Err: {}", GetLastError());
		return { 0,0 };
	}
	
	//initialize each section (.text, .data) correctly to its virtual address, offsets wont match in file, this is why its needed.
	IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (uint32_t i = 0; i != fileHeader->NumberOfSections; ++i, ++SectionHeader) {
		if (SectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(handle, (LPVOID)((BYTE*)allocBase + SectionHeader->VirtualAddress), dllBytes + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData, 0)) {
				spdlog::error("Failed to write dll section: {}", GetLastError());
			}
		}
	}

	std::stringstream ss1; ss1 << std::hex << allocBase;
	std::stringstream ss2; ss2 << std::hex << (ULONGLONG)allocBase + optHeader->AddressOfEntryPoint;

	spdlog::info("Allocated dll in process at {} (entry: {})", "0x" + ss1.str(), "0x" + ss2.str());
	return { (ULONGLONG)allocBase,optHeader->SizeOfImage };
}

ManualMapper::FunctionResult ManualMapper::_parseFunction(ULONGLONG funcBase, ULONGLONG size)
{
	std::vector<UCHAR> functionBytes;
	UCHAR* currentByte = reinterpret_cast<UCHAR*>(funcBase);

	for(ULONGLONG i = 0; i < size; i++) {
		UCHAR opcode = *currentByte;

		functionBytes.push_back(opcode);

		currentByte++;

	}

	return { functionBytes,funcBase };
}

ULONGLONG ManualMapper::_calculateLocalFuncSize(ULONGLONG funcBase)
{
	ULONGLONG size = 0;
	while (*(ULONG*)(funcBase+size) != END_MARKER_SIG) {
		size++;
	}
	const size_t kSize = size;

	while (size - kSize < 16) {
		switch ((*(UCHAR*)(funcBase + size))){
		
		case 0xC2: {
			return size + 3;
		}
		case 0xC3: {
			return size;
		}
		case 0xCC: {
			if (size == kSize + 3) {
				return size;
			}
		}
		}
		size++;
	}
	return size;
}
ManualMapper::Detour ManualMapper::_createDllDetour(HANDLE handle, LPVOID detourLocal, ULONGLONG stub, ULONGLONG dllAddr)
{
	ULONGLONG statusAddr = (ULONGLONG)_createStatus(handle);

	std::vector<ULONGLONG> stack = {};
	stack.push_back(dllAddr);
	stack.push_back(statusAddr);

	HMODULE kernelBase = MemExternal::getLoadedModule(handle, "KERNELBASE.dll");
	HMODULE ntdll = MemExternal::getLoadedModule(handle, "ntdll.dll");
	HMODULE kernel32 = MemExternal::getLoadedModule(handle, "KERNEL32.DLL");

	ULONGLONG pLoadLibraryA = (ULONGLONG)kernelBase + MemExternal::getExportsFunctions(handle, kernelBase).at("LoadLibraryA");
	stack.push_back(pLoadLibraryA);
	ULONGLONG pGetProcAddress = (ULONGLONG)kernelBase + MemExternal::getExportsFunctions(handle, kernelBase).at("GetProcAddress");
	stack.push_back(pGetProcAddress);
	ULONGLONG pGetModuleHandleA = (ULONGLONG)kernelBase + MemExternal::getExportsFunctions(handle, kernelBase).at("GetModuleHandleA");
	stack.push_back(pGetModuleHandleA);


	Detour detour = _createDetour({ 0 }, handle, detourLocal, stub, stack, statusAddr);


	ULONG oldProt;
	ULONGLONG lastStatus = -1;
	while (true) {
		ULONGLONG status = 0;
		if (!ReadProcessMemory(handle, (LPVOID)statusAddr, &status, sizeof(status), 0)) {
			spdlog::error("Failed to read status! Err: {}", GetLastError());
			break;
		}

		if (lastStatus != status) {
			spdlog::info("Status: {}", status);
			//restore parts of the hook
			if (lastStatus <= 0 && status != Status::STATUS_UNSET) {
				FlushInstructionCache(handle, (LPVOID)stub, 14);
				VirtualProtectEx(handle, (LPVOID)(stub + 6), sizeof(ULONGLONG), PAGE_EXECUTE_READ, &oldProt);
				if (MemExternal::readJmpAbs(handle, stub) != detour.originalJmp) {
					spdlog::warn("hook failed to restore original jmp in function. . . Doing it manually");
					MemExternal::writeJmpAbs(handle, stub, detour.originalJmp);
				}
			}
		}
		ULONG exitCode;
		if (exitCode = GetExitCodeProcess(handle, &exitCode)) {
			if (exitCode != STILL_ACTIVE && WaitForSingleObject(handle, 0) != WAIT_TIMEOUT) {
				spdlog::error("process ended during inject. . . code: {}", exitCode);
				break;
			}
		}
		if (status == Status::STATUS_SUCCESS) {
			spdlog::info("Injected!");

			//free memory!
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQueryEx(handle, (LPVOID)dllAddr, &mbi, sizeof(mbi))) {
				ULONG oldProt;
				VirtualProtectEx(handle, mbi.AllocationBase, mbi.RegionSize, PAGE_EXECUTE_READ, &oldProt);
			}
			VirtualFreeEx(handle, (LPVOID)detour.allocAddr, 0, MEM_FREE);
			VirtualFreeEx(handle, (LPVOID)statusAddr, 0, MEM_FREE);
			break;
		}
		lastStatus = status;
	}

	return detour;
}
ManualMapper::Detour ManualMapper::_createDetour(Allocation optPreAllocatedData, HANDLE handle, LPVOID detourLocal, ULONGLONG stub,std::vector<ULONGLONG> stack, ULONGLONG statusAddr) {

	ULONG oldLocalDetourProt;
	if (VirtualProtect(detourLocal, 0x1000, PAGE_EXECUTE_READWRITE, &oldLocalDetourProt));

	FunctionResult parsedFunction = _parseFunction((ULONGLONG)detourLocal, _calculateLocalFuncSize((ULONGLONG)detourLocal));
	ULONGLONG targetFuncSize = parsedFunction.funcBytes.size();

	ULONGLONG originalJmp = MemExternal::readJmpAbs(handle, stub);

	//get func bytes, +200 as buffer for extra wrapping we add
	UCHAR* funcBytes = new UCHAR[targetFuncSize + 200];
	UCHAR* targetFunctionBytes = funcBytes;
	if (statusAddr) {
		//restore the original jump
		//mov rax, stub
		*(UCHAR*)funcBytes = 0x48;
		*(UCHAR*)(funcBytes + 1) = 0xB8;
		*(ULONGLONG*)(funcBytes + 2) = stub + 6;

		//mov rcx, original
		*(UCHAR*)(funcBytes + 10) = 0x48;
		*(UCHAR*)(funcBytes + 11) = 0xB9;
		*(ULONGLONG*)(funcBytes + 12) = originalJmp;

		//mov [rax], rcx
		*(UCHAR*)(funcBytes + 20) = 0x48;
		*(UCHAR*)(funcBytes + 21) = 0x89;
		*(UCHAR*)(funcBytes + 22) = 0x08;

		targetFunctionBytes += 23;

		//set the status to the hook was ran
		*(UCHAR*)targetFunctionBytes = 0x48;
		*(UCHAR*)(targetFunctionBytes + 1) = 0xB8;
		*(ULONGLONG*)(targetFunctionBytes + 2) = statusAddr;
		*(UCHAR*)(targetFunctionBytes + 10) = 0xC7;
		*(UCHAR*)(targetFunctionBytes + 11) = 0x00;
		*(ULONG*)(targetFunctionBytes + 12) = Status::STATUS_1;

		targetFunctionBytes += 16;
	}

	//copy the detour function bytes
	memcpy(targetFunctionBytes, parsedFunction.funcBytes.data(), parsedFunction.funcBytes.size());

	//allocate memory for entire detour
	LPVOID detourFunctionAlloc = (LPVOID)optPreAllocatedData.base;
	ULONGLONG detourFunctionSize = optPreAllocatedData.size;
	if (!detourFunctionAlloc) {
		detourFunctionSize = 0x1000;
		detourFunctionAlloc = VirtualAllocEx(handle, nullptr, detourFunctionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (detourFunctionAlloc) {
			std::stringstream ss; ss << std::hex << detourFunctionAlloc;
			spdlog::info("detour allocated at {}", "0x" + ss.str());
		}
		else {
			spdlog::error("failed to allocate memory for detour.");
			return { 0 };
		}
	}

	//replace its stack placeholders with the real addr were going to use
	//stack is located in the allocation right after the function
	ULONGLONG stackAddr = (ULONGLONG)detourFunctionAlloc + targetFuncSize + 250;

	for (ULONGLONG offset = 0; offset < targetFuncSize; offset++) {
		UCHAR* currentBytes = targetFunctionBytes + offset;
		if (*(ULONGLONG*)(currentBytes) == STACK_PLACEHOLDER) {
			*(ULONGLONG*)(currentBytes) = stackAddr;
			offset += sizeof(ULONGLONG);
			continue;
		}
	}


	{
		//right at the end
		UCHAR* currentBytes = targetFunctionBytes + targetFuncSize;

		//set the status
		if (statusAddr) {
			*(UCHAR*)currentBytes = 0x48;
			*(UCHAR*)(currentBytes + 1) = 0xB8;
			*(ULONGLONG*)(currentBytes + 2) = statusAddr;
			*(UCHAR*)(currentBytes + 10) = 0xC7;
			*(UCHAR*)(currentBytes + 11) = 0x00;
			*(ULONG*)(currentBytes + 12) = Status::STATUS_SUCCESS;

			currentBytes+=16;
		}
		
		//redirect control flow back to where it was supposed to go
		*(UCHAR*)(currentBytes) = 0xFF;
		*(UCHAR*)(currentBytes + 1) = 0x25;
		*(ULONG*)(currentBytes + 2) = 0x00000000;
		*(ULONGLONG*)(currentBytes + 6) = ((ULONGLONG)originalJmp);

	}


	//write the stack
	ULONGLONG stackAddrEnum = stackAddr;
	for (ULONGLONG each : stack) {
		if (!WriteProcessMemory(handle, (LPVOID)stackAddrEnum, &each, sizeof(ULONGLONG), 0)) {
			spdlog::error("Failed to write stack data! Err: {}", GetLastError());
			break;
		}
		stackAddrEnum += sizeof(ULONGLONG);
	}

	if (!WriteProcessMemory(handle, detourFunctionAlloc, funcBytes, targetFuncSize + 200, 0)) {
		spdlog::error("Failed to write target func byte data! Err: {}", GetLastError());
	}

	//we have to make the piece of memory that had our original jump writable so that our detour code can restore it
	ULONG oldProt;
	VirtualProtectEx(handle, (LPVOID)(stub + 6), sizeof(ULONGLONG), PAGE_EXECUTE_READWRITE, &oldProt);

	MemExternal::writeJmpAbs(handle, stub, (ULONGLONG)detourFunctionAlloc);
	FlushInstructionCache(handle, (LPVOID)stub, 14);
	delete[] funcBytes;

	return { (ULONGLONG)detourFunctionAlloc,detourFunctionSize,originalJmp };
}

LPVOID ManualMapper::_createStatus(HANDLE handle)
{
	LPVOID allocBase = VirtualAllocEx(handle, 0, sizeof(ULONGLONG), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!allocBase) {
		spdlog::error("Failed to allocate memory for status in target process. Err: {}", GetLastError());
		return 0;
	}
	
	Status newStatus = STATUS_UNSET;
	if (!WriteProcessMemory(handle, allocBase, &newStatus, sizeof(Status), 0)) {
		spdlog::error("Failed to write start status in target process. Err: {}", GetLastError());
		return 0;
	}

	return allocBase;
}
	