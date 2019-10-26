#pragma once
#include <string>
#include "checked_cast.hpp"

template <int width = 1>
inline std::wstring to_hexwstring(unsigned long long val)
{
	wchar_t buf[std::max(checked_cast<int>(sizeof(val)) * 2, width) + 1];
	std::swprintf(buf, std::size(buf), L"%0*llx", width, val);
	return buf;
}

template <int width = 1>
inline std::wstring to_hexwstring(unsigned long val)
{
	wchar_t buf[std::max(checked_cast<int>(sizeof(val)) * 2, width) + 1];
	std::swprintf(buf, std::size(buf), L"%0*lx", width, val);
	return buf;
}

template <int width = 1>
inline std::wstring to_hexwstring(long val)
{
	return to_hexwstring<width>(checked_cast<unsigned long>(val));
}
