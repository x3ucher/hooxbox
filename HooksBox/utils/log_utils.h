#ifndef LOG_UTILS_H
#define LOG_UTILS_H

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cwctype>


// Для отладки - вывод в консоль отладчика
void DebugPrint(const char* text);
void DebugPrintW(const wchar_t* text);
bool EqualsCaseInsensitive(const std::wstring& str1, const std::wstring& str2);

#endif // LOG_UTILS_H