#pragma once
#include <spdlog/spdlog.h>
#include "memory.hpp"
#include "globals.hpp"
namespace ManualMapper {
	struct Detour {
		ULONGLONG stubAddr;
		ULONGLONG stubSize;
		ULONGLONG targetAddr;
	};
	enum Status {
		STATUS_BUSY,
		STATUS_1,
		STATUS_2,
		STATUS_3,
		STATUS_4,
		STATUS_SUCCESS,
	};

	//allocates and writes the dll to the target process
	HMODULE _allocDll(HANDLE handle, const std::string& dllPath);

	//alloctes a piece of memory to hold the status of the hook, for communication internal and external
	LPVOID _createStatus(HANDLE handle);

	//this detour will be jmped to by our hooked function which will then jmp to our dll :D
	//this function writes the function bytes of the detour and allocates valuable data with it
	//return statement exclusive
	ULONGLONG _calculateLocalFuncSize(ULONGLONG funcBase);

	template<typename RetType, typename ...Args>
	ULONGLONG _createDetour(HANDLE handle, RetType(*targetFunction)(Args...), ULONGLONG dllAddr, ULONGLONG stub, ULONGLONG f) {

		MemExternal::suspendByfronThreads(handle);
		ULONGLONG targetFuncSize = _calculateLocalFuncSize((ULONGLONG)targetFunction);
		ULONGLONG statusAddr = (ULONGLONG)_createStatus(handle);
		ULONGLONG originalJmp = MemExternal::readJmpAbs(handle, stub);

		//get func bytes
		UCHAR* funcBytes = new UCHAR[targetFuncSize+200];
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

		UCHAR* targetFunctionBytes = funcBytes + 23;

		//set the status to the hook was ran
		*(UCHAR*)targetFunctionBytes = 0x48;
		*(UCHAR*)(targetFunctionBytes + 1) = 0xB8;
		*(ULONGLONG*)(targetFunctionBytes + 2) = statusAddr;
		*(UCHAR*)(targetFunctionBytes + 10) = 0xC7;
		*(UCHAR*)(targetFunctionBytes + 11) = 0x00;
		*(ULONG*)(targetFunctionBytes + 12) = Status::STATUS_1;

		targetFunctionBytes += 16;
		//copy the detour function bytes
		memcpy(targetFunctionBytes, (LPVOID)((ULONGLONG)targetFunction), targetFuncSize);

		//allocate memory for entire detour
		LPVOID detourFunctionAlloc = VirtualAllocEx(handle, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		//replace its stack placeholders with the real addr were going to use
		//stack is located in the allocation right after the function

		ULONGLONG stackAddr = (ULONGLONG)detourFunctionAlloc + targetFuncSize+200;

		for (ULONGLONG offset = 0; offset < targetFuncSize; offset++) {
			UCHAR* currentBytes = targetFunctionBytes + offset;
			if (*(ULONGLONG*)(currentBytes) == SCF_STACK_PLACEHOLDER) {
				*(ULONGLONG*)(currentBytes) = stackAddr;
				offset += sizeof(ULONGLONG);
				continue;
			}
		}


		{
			//right at the end
			UCHAR* currentBytes = targetFunctionBytes + targetFuncSize;

			//set the status
			*(UCHAR*)currentBytes = 0x48;
			*(UCHAR*)(currentBytes + 1) = 0xB8;
			*(ULONGLONG*)(currentBytes + 2) = statusAddr;
			*(UCHAR*)(currentBytes + 10) = 0xC7;
			*(UCHAR*)(currentBytes + 11) = 0x00;
			*(ULONG*)(currentBytes + 12) = Status::STATUS_SUCCESS;

			UCHAR* currentBytes1 = currentBytes + 16;

			//redirect control flow back to where it was supposed to go
			*(UCHAR*)(currentBytes1) = 0xFF;
			*(UCHAR*)(currentBytes1 + 1) = 0x25;
			*(ULONG*)(currentBytes1 + 2) = 0x00000000;
			*(ULONGLONG*)(currentBytes1 + 6) = ((ULONGLONG)originalJmp);

		}


		//fill the stack with actual data
		std::vector<ULONGLONG> stack = {};
		stack.push_back(dllAddr);
		stack.push_back(statusAddr);

		HMODULE kernelBase = MemExternal::getLoadedModule(handle,"KERNELBASE.dll");
		ULONGLONG pLoadLibraryA = (ULONGLONG)GetProcAddress(kernelBase, "LoadLibraryA");
		stack.push_back(pLoadLibraryA);
		ULONGLONG pGetProcAddress = (ULONGLONG)GetProcAddress(kernelBase, "GetProcAddress");
		stack.push_back(pGetProcAddress);
		ULONGLONG pGetModuleHandleA = (ULONGLONG)GetProcAddress(kernelBase, "GetModuleHandleA");
		stack.push_back(pGetModuleHandleA);

		HMODULE kernel32 = MemExternal::getLoadedModule(handle, "kernel32.dll");
		ULONGLONG pRtlAddFunctionTable = (ULONGLONG)GetProcAddress(kernelBase, "RtlAddFunctionTable");
		stack.push_back(pRtlAddFunctionTable);

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

		MemExternal::writeJmpAbs(handle, stub, (ULONGLONG)detourFunctionAlloc);
		FlushInstructionCache(handle, (LPVOID)stub, 12);

		//we have to make the piece of memory that had our original jump writable so that our detour code and restore it
		ULONG oldProt;
		VirtualProtectEx(handle, (LPVOID)(stub + 6), sizeof(ULONGLONG), PAGE_EXECUTE_READWRITE, &oldProt);

		while (true) {
			ULONG status = 0;
			if (!ReadProcessMemory(handle, (LPVOID)statusAddr, &status, sizeof(status), 0)) {
				spdlog::error("Failed to read status! Err: {}", GetLastError());
				break;
			}
			spdlog::info("Status: {}", status);
			if (status == Status::STATUS_SUCCESS) {
				spdlog::info("successfully reached the end of the hook");
				MemExternal::resumeByfronThreads(handle);

				//VirtualFreeEx(handle, detourFunctionAlloc, targetFuncSize + 200, MEM_RELEASE);
				//VirtualProtectEx(handle, (LPVOID)(stub + 6), sizeof(ULONGLONG), PAGE_EXECUTE, &oldProt);

				break;
			}
		}

		delete[] funcBytes;
		return (ULONGLONG)detourFunctionAlloc;
	}

	//the main function, does all the shit
	void inject(HANDLE handle, const std::string& dllPath);
}