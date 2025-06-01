#pragma once
#include <spdlog/spdlog.h>
#include "memory.hpp"
#include "globals.hpp"

namespace ManualMapper {
	struct Detour {
		ULONGLONG allocAddr;
		ULONGLONG size;
		ULONGLONG originalJmp;
	};
	struct Allocation {
		ULONGLONG base;
		ULONGLONG size;
	};
	struct FunctionResult {
		std::vector<UCHAR> funcBytes;
		ULONGLONG base;
	};
	enum Status {
		STATUS_UNSET,
		STATUS_1,
		STATUS_2,
		STATUS_3,
		STATUS_4,
		STATUS_SUCCESS,
	};

	//allocates and writes the dll to the target process
	Allocation _allocDll(HANDLE handle, const std::string& dllPath);
	//alloctes a piece of memory to hold the status of the hook, for communication internal and external
	LPVOID _createStatus(HANDLE handle);

	//this detour will be jmped to by our hooked function which will then jmp to our dll :D
	//this function writes the function bytes of the detour and allocates valuable data with it
	//return statement exclusive
	FunctionResult _parseFunction(ULONGLONG funcBase, ULONGLONG size);
	ULONGLONG _calculateLocalFuncSize(ULONGLONG funcBase);

	Detour _createDetour(
		Allocation optPreAllocatedData, //if you already allocated memory in the target process you can pass it in here
		HANDLE handle, 
		LPVOID detourLocal, //the base address of the local detour function
		ULONGLONG stub, //the place where the absolute jmp were overriding is
		std::vector<ULONGLONG> stack, //the variables that the detour can use
		ULONGLONG statusAddr = 0 //during the hook, will move numbers into this address to signal the step in the hook its in
		//if status addr is set, it will also automatically restore the hook when its run once
	);

	Detour _createDllDetour(HANDLE handle, LPVOID detourLocal, ULONGLONG stub, ULONGLONG dllAddr);

	//the main function, does all the shit
	void inject(HANDLE handle, const std::string& dllPath);
}