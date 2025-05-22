#pragma once
#include <vector>
#include <string>

namespace Util {
	void setTextColor(int color);
	void resetTextColor();
	std::vector<unsigned char> readFile(const std::string& path);
}