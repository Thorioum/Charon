
#include <iostream>
#include <spdlog/spdlog.h>
#include <argparse/argparse.hpp>

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


	argparse::ArgumentParser parser("Charon");

	parser.add_description(
		"A Manual Map DLL Injector for Roblox. Most probably detected. Features absolutely no smart bypasses and your dll threads will probably cease to function after 30 seconds or so");
	parser.add_epilog("https://thorioum.net");
	parser.add_argument("-d", "--dll").required().help("the path to the dll to inject");
	try
	{
		parser.parse_args(argc, argv);
	}
	catch (const std::exception& ex)
	{
		spdlog::error("Error Parsing Args: {}", ex.what());
		return 1;
	}

	std::string dllPath = parser.get< std::string >("dll");
	spdlog::info("Waiting for RobloxPlayerBeta.exe. . .");
	while (FindWindowW(nullptr, L"Roblox") == NULL)
	{
		Sleep(200);
	}
	HANDLE robloxHandle = MemExternal::WaitForProcess(PROCESS_ALL_ACCESS, FALSE, "RobloxPlayerBeta.exe").first;

	spdlog::info("Succesfully opened handle to Roblox!");

	ManualMapper::inject(robloxHandle, dllPath);

	CloseHandle(robloxHandle);
}