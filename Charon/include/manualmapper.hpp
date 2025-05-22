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
		STATUS_ERROR,
		STATUS_SUCCESS,
	};

	//allocates and writes the dll to the target process
	HMODULE _allocDll(HANDLE handle, const std::string& dllPath);

	//this detour will be jmped to by our hooked function which will then jmp to our dll :D
	//this function writes the function bytes of the detour and allocates valuable data with it
	ULONGLONG _calculateLocalFuncSize(ULONGLONG funcBase);

	template<typename RetType, typename ...Args>
	ULONGLONG _createDetour(HANDLE handle, RetType(*targetFunction)(Args...), ULONGLONG dllAddr, ULONGLONG stub, ULONGLONG f) {


		ULONGLONG targetFuncSize = _calculateLocalFuncSize((ULONGLONG)targetFunction);

		//get func bytes
		UCHAR* targetFunctionBytes = new UCHAR[targetFuncSize];
		std::memcpy(targetFunctionBytes, targetFunction, targetFuncSize);

		LPVOID detourFunctionAlloc = VirtualAllocEx(handle, nullptr, targetFuncSize+100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		//replace its stack placeholders with the real addr were going to use
		//stack is located in the allocation right after the function
		ULONGLONG stackAddr = (ULONGLONG)detourFunctionAlloc + targetFuncSize+10;

		ULONGLONG original = MemExternal::readJmpRip(handle, stub);

		for (ULONGLONG offset = 0; offset < targetFuncSize; offset++) {
			UCHAR* currentBytes = targetFunctionBytes + offset;
			if (*(ULONGLONG*)(currentBytes) == SCF_STACK_PLACEHOLDER) {
				*(ULONGLONG*)(currentBytes) = stackAddr;
				offset += sizeof(ULONGLONG);
				continue;
			}
			if (*(ULONG*)(currentBytes) == SCF_END_MARKER) {
				*(UCHAR*)(currentBytes) = 0xFF; 
				*(UCHAR*)(currentBytes+1) = 0x25;
				*(ULONG*)(currentBytes+2) = 0x00000000;
				*(ULONGLONG*)(currentBytes+6) = original;

			}
		}

		//fill the stack with actual data
		std::vector<ULONGLONG> stack = {};
		stack.push_back(original);

		//write the stack
		ULONGLONG stackAddrEnum = stackAddr;
		for (ULONGLONG each : stack) {
			if (!WriteProcessMemory(handle, (LPVOID)stackAddrEnum, &each, sizeof(ULONGLONG), 0)) {
				spdlog::error("Failed to write stack data! Err: {}", GetLastError());
				break;
			}
			stackAddrEnum += sizeof(ULONGLONG);
		}

		*(UCHAR*)(targetFunctionBytes) = 0x4C;//mov            r10, rcx
		*(UCHAR*)(targetFunctionBytes +1) = 0x8B;
		*(UCHAR*)(targetFunctionBytes +2) = 0xD1;

		*(UCHAR*)(targetFunctionBytes + 3) = 0xB8;
		*(UCHAR*)(targetFunctionBytes + 4) = 0x36;
		*(UCHAR*)(targetFunctionBytes + 5) = 0x00;
		*(UCHAR*)(targetFunctionBytes + 6) = 0x00;
		*(UCHAR*)(targetFunctionBytes + 7) = 0x00;//mov            eax, 0x36

		UCHAR* currentBytes = targetFunctionBytes+8;

		*(UCHAR*)(currentBytes) = 0xFF;
		*(UCHAR*)(currentBytes + 1) = 0x25;
		*(ULONG*)(currentBytes + 2) = 0x00000000;
		*(ULONGLONG*)(currentBytes + 6) = ((ULONGLONG)f+8);

		//write the func
		if (!WriteProcessMemory(handle, detourFunctionAlloc, targetFunctionBytes, targetFuncSize, 0)) {
			spdlog::error("Failed to write target func byte data! Err: {}", GetLastError());
		}

		MemExternal::writeJmpRip(handle, stub, (ULONGLONG)detourFunctionAlloc);

		delete[] targetFunctionBytes;
		return (ULONGLONG)detourFunctionAlloc;
	}
	//alloctes a piece of memory to hold the status of the hook, for communication internal and external
	ULONGLONG _createStatus(HANDLE handle);

	//the main function, does all the shit
	void inject(HANDLE handle, const std::string& dllPath);
}