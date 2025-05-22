#include "../include/util.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <fstream>

void Util::setTextColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}
void Util::resetTextColor() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

std::vector<UCHAR> Util::readFile(const std::string& path)
{
	std::ifstream stream = std::ifstream(path,  std::ios::ate | std::ios::binary);

	if (!stream.is_open()) {
		return {};
	}

	size_t fileSize = static_cast<size_t>(stream.tellg());
	stream.seekg(0, std::ios::beg);

	std::vector<UCHAR> buffer(fileSize);

	if (!stream.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
		return {};
	}

	return buffer;
	
}
