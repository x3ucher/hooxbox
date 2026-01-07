#ifndef LOG_UTILS_H
#define LOG_UTILS_H

#include <windows.h>
#include <string>

// Для отладки - вывод в консоль отладчика
void DebugPrint(const char* text);
void DebugPrintW(const wchar_t* text);

#endif // LOG_UTILS_H