#ifndef LOG_UTILS_H
#define LOG_UTILS_H

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cwctype>


// Debug-output helpers (OutputDebugStringA/W).
void DebugPrint(const char* text);
void DebugPrintW(const wchar_t* text);
bool EqualsCaseInsensitive(const std::wstring& str1, const std::wstring& str2);

// Thread-safe UTF-8 file logger.  Writes one timestamped line per call to
// "sandbox_evasion.log" in the process working directory.  The first write
// to an empty file emits the UTF-8 BOM.
void WriteFileLog(const wchar_t* level, const std::wstring& msg);

#endif // LOG_UTILS_H
