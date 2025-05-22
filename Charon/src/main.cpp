
#include <iostream>
#include <spdlog/spdlog.h>
#include "../include/manualmapper.hpp"
#include "../include/util.hpp"
int main(int argc, char* argv[]) {

	
	Util::setTextColor(4);
	std::cout << 
		"  ,ad8888ba,   88                                                                       \n"
		"d8\"'     `\"8b  88															         \n"
		"d8\'            88                                                                      \n"
		"88             88, dPPYba, , adPPYYba,  8b,dPPYba,  ,adPPYba,    8b,dPPYba,             \n"
		"88             88P\'    \"8a  \"\"     `Y8  88P\'   \"Y8  a8\"     \"8a  88P\'   `\"8a  \n"
		"Y8,            88       88  ,adPPPPP88  88          8b       d8  88       88            \n"
		"Y8a.     .a8P  88       88  88, ,   88  88          \"8a,   ,a8\"  88       88          \n"
		"`\"Y8888Y\"\'     88       88  `\"8bbdP\"Y8  88           `\"YbbdP\"\'   88       88    \n";
	Util::resetTextColor();

	spdlog::info("Waiting for RobloxPlayerBeta.exe. . .");
	HANDLE robloxHandle = MemExternal::WaitForProcess(PROCESS_ALL_ACCESS, FALSE, "RobloxPlayerBeta.exe").first;
	spdlog::info("Succesfully opened handle to Roblox!");

	ManualMapper::inject(robloxHandle, "test.dll");

	CloseHandle(robloxHandle);
}