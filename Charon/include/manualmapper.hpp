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
		STATUS_RUNNING,
		STATUS_SUCCESS,
	};

	//allocates and writes the dll to the target process
	HMODULE _allocDll(HANDLE handle, const std::string& dllPath);

	//alloctes a piece of memory to hold the status of the hook, for communication internal and external
	LPVOID _createStatus(HANDLE handle);

	//this detour will be jmped to by our hooked function which will then jmp to our dll :D
	//this function writes the function bytes of the detour and allocates valuable data with it
	ULONGLONG _calculateLocalFuncSize(ULONGLONG funcBase);

	template<typename RetType, typename ...Args>
	ULONGLONG _createDetour(HANDLE handle, RetType(*targetFunction)(Args...), ULONGLONG dllAddr, ULONGLONG stub, ULONGLONG f) {

		MemExternal::suspendThreads(handle);
		ULONGLONG targetFuncSize = _calculateLocalFuncSize((ULONGLONG)targetFunction)+80;
		ULONGLONG statusAddr = (ULONGLONG)_createStatus(handle);

		//get func bytes
		UCHAR* funcBytes = new UCHAR[targetFuncSize];
		const UCHAR prologue[] = {
			// Prologue
			0x55,                               // push rbp
			0x48, 0x89, 0xE5,                   // mov rbp, rsp
			0x48, 0x83, 0xEC, 0x32,             // sub rsp, 0x32

			// Preserve registers
			0x50,                               // push rax
			0x51,                               // push rcx
			0x52,                               // push rdx
			0x41, 0x50,                         // push r8
			0x41, 0x51,						    // push r9
		};
		const UCHAR epilogue[] = {
			// Restore registers
			0x41, 0x59,                         // pop r9
			0x41, 0x58,                         // pop r8
			0x5A,                               // pop rdx
			0x59,                               // pop rcx
			0x58,                               // pop rax

			// Epilogue
			0x48, 0x89, 0xEC,                   // mov rsp, rbp
			0x5D,       				    // push r9
		};
		memcpy(funcBytes, prologue, sizeof(prologue));
		UCHAR* targetFunctionBytes = funcBytes + sizeof(prologue);

		*(UCHAR*)targetFunctionBytes = 0x48;
		*(UCHAR*)(targetFunctionBytes + 1) = 0xB8;
		*(ULONGLONG*)(targetFunctionBytes + 2) = statusAddr;
		*(UCHAR*)(targetFunctionBytes + 10) = 0xC7;
		*(UCHAR*)(targetFunctionBytes + 11) = 0x00;
		*(ULONG*)(targetFunctionBytes + 12) = Status::STATUS_RUNNING;

		targetFunctionBytes += 16;

		memcpy(targetFunctionBytes, targetFunction, targetFuncSize-80);


		LPVOID detourFunctionAlloc = VirtualAllocEx(handle, nullptr, targetFuncSize+100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		//replace its stack placeholders with the real addr were going to use
		//stack is located in the allocation right after the function

		ULONGLONG stackAddr = (ULONGLONG)detourFunctionAlloc + targetFuncSize+40;
		ULONGLONG originalJmp = MemExternal::readJmpRip(handle, stub);

		for (ULONGLONG offset = 0; offset < targetFuncSize; offset++) {
			UCHAR* currentBytes = targetFunctionBytes + offset;
			if (*(ULONGLONG*)(currentBytes) == SCF_STACK_PLACEHOLDER) {
				*(ULONGLONG*)(currentBytes) = stackAddr;
				offset += sizeof(ULONGLONG);
				continue;
			}
			if (*(ULONG*)(currentBytes) == SCF_END_MARKER) {

				*(UCHAR*)currentBytes = 0x48;
				*(UCHAR*)(currentBytes + 1) = 0xB8;
				*(ULONGLONG*)(currentBytes + 2) = statusAddr;
				*(UCHAR*)(currentBytes + 10) = 0xC7;
				*(UCHAR*)(currentBytes + 11) = 0x00;
				*(ULONG*)(currentBytes + 12) = Status::STATUS_SUCCESS;

				/*
				//push rax and rcx
				*(UCHAR*)(currentBytes + 16) = 0x50;
				*(UCHAR*)(currentBytes + 17) = 0x51;

				UCHAR* currentBytes1 = currentBytes + 18;

				//mov rax, stub
				*(UCHAR*)currentBytes1 = 0x48;
				*(UCHAR*)(currentBytes1 + 1) = 0xB8;
				*(ULONGLONG*)(currentBytes1 + 2) = stub + 6;

				//mov rcx, original
				*(UCHAR*)(currentBytes1 + 10) = 0x48;
				*(UCHAR*)(currentBytes1 + 11) = 0xB9;
				*(ULONGLONG*)(currentBytes1 + 12) = originalJmp;

				//mov [rax], rcx
				*(UCHAR*)(currentBytes1 + 20) = 0x48;
				*(UCHAR*)(currentBytes1 + 21) = 0x89;
				*(UCHAR*)(currentBytes1 + 22) = 0x08;

				//pop rax and rcx
				*(UCHAR*)(currentBytes1 + 23) = 0x59;
				*(UCHAR*)(currentBytes1 + 24) = 0x58;

				*(UCHAR*)(currentBytes1 + 25) = 0x5F;
				*(UCHAR*)(currentBytes1 + 26) = 0x5D;
				*/

				UCHAR* currentBytes2 = currentBytes + 16;
				memcpy(currentBytes2, epilogue, sizeof(epilogue));
				currentBytes2 += sizeof(epilogue);

				*(UCHAR*)(currentBytes2) = 0xFF;
				*(UCHAR*)(currentBytes2 + 1) = 0x25;
				*(ULONG*)(currentBytes2 + 2) = 0x00000000;
				*(ULONGLONG*)(currentBytes2 + 6) = ((ULONGLONG)originalJmp);
				
				
				break;
			}
		}

		//fill the stack with actual data
		std::vector<ULONGLONG> stack = {};
		stack.push_back(originalJmp);

		//write the stack
		ULONGLONG stackAddrEnum = stackAddr;
		for (ULONGLONG each : stack) {
			if (!WriteProcessMemory(handle, (LPVOID)stackAddrEnum, &each, sizeof(ULONGLONG), 0)) {
				spdlog::error("Failed to write stack data! Err: {}", GetLastError());
				break;
			}
			stackAddrEnum += sizeof(ULONGLONG);
		}



		if (!WriteProcessMemory(handle, detourFunctionAlloc, funcBytes, targetFuncSize, 0)) {
			spdlog::error("Failed to write target func byte data! Err: {}", GetLastError());
		}

		MemExternal::writeJmpRip(handle, stub, (ULONGLONG)detourFunctionAlloc);
		FlushInstructionCache(handle, (LPVOID)stub, 12);
		//MemExternal::resumeThreads(handle);

		ULONG oldProt;
		VirtualProtectEx(handle, (LPVOID)(stub+6), sizeof(ULONGLONG), PAGE_EXECUTE_READWRITE, &oldProt);

		while (true) {
			ULONG status = 0;
			if (!ReadProcessMemory(handle, (LPVOID)statusAddr, &status, sizeof(status), 0)) {
				spdlog::error("Failed to read status! Err: {}", GetLastError());
				break;
			}
			spdlog::info("Status: {}", status);
			if (status != 0) {
				//MemExternal::suspendThreads(handle);
				MemExternal::writeJmpRip(handle, stub, (ULONGLONG)originalJmp);

				break;
			}
		}

		delete[] funcBytes;
		return (ULONGLONG)detourFunctionAlloc;
	}

	//the main function, does all the shit
	void inject(HANDLE handle, const std::string& dllPath);
}