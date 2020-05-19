#pragma once

#include "pch.h"

#define DLLEXPORT extern "C" __declspec(dllexport)

typedef void(WINAPI* FindHooks)();
typedef void(WINAPI* ProcessEvent)(DWORD processId);
typedef void(WINAPI* OnCreateThread)(int64_t thread_id, DWORD processId, uint64_t addr, uint64_t context, uint64_t subcontext, LPCWSTR name, LPCWSTR hookcode);
typedef void(WINAPI* OnRemoveThread)(int64_t thread_id);
typedef void(WINAPI* OutputText)(int64_t thread_id, LPCWSTR output);

namespace TextHost
{
	DLLEXPORT DWORD WINAPI TextHostInit(ProcessEvent connect, ProcessEvent disconnect, OnCreateThread create, OnRemoveThread remove, OutputText output);
	DLLEXPORT DWORD WINAPI InjectProcess(DWORD processId);
	DLLEXPORT DWORD WINAPI DetachProcess(DWORD processId);
	DLLEXPORT DWORD WINAPI InsertHook(DWORD processId, LPCWSTR command);
	DLLEXPORT DWORD WINAPI RemoveHook(DWORD processId, uint64_t address);
	DLLEXPORT DWORD WINAPI SearchForText(DWORD processId, LPCWSTR text, int codepage);
	DLLEXPORT VOID WINAPI SearchForHooks(DWORD processId, SearchParam* sp, FindHooks findhooks);
	DLLEXPORT DWORD WINAPI AddClipboardThread(HWND handle);
}