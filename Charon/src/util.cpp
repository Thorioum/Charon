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
	std::ifstream file = std::ifstream(path,  std::ios::ate | std::ios::binary);
	file.seekg(0, std::ios::end);
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<UCHAR> buffer(size);
	if (file.read((char*)buffer.data(), size)) {
		return buffer;
	}

	return {};
	
}
