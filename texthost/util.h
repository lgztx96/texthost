#pragma once

#include "wow64ext.h"

enum class InjectResult {
    OK,
    Error_OpenProcess,
    Error_VirtualAllocEx,
    Error_GetProcAddress,
    Error_WriteProcessMemory,
    Error_CreateRemoteThread
};

InjectResult Wow64InjectWin64(DWORD dwProcessId, const std::wstring& filename);

BOOL Is64BitProcess(HANDLE hProcess);