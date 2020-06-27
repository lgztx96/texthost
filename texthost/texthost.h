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
	DLLEXPORT BOOL WINAPI TextHostInit(ProcessEvent connect, ProcessEvent disconnect, OnCreateThread create, OnRemoveThread remove, OutputText output);
	DLLEXPORT VOID WINAPI InjectProcess(DWORD processId);
	DLLEXPORT VOID WINAPI DetachProcess(DWORD processId);
	DLLEXPORT VOID WINAPI InsertHook(DWORD processId, LPCWSTR command);
	DLLEXPORT VOID WINAPI RemoveHook(DWORD processId, uint64_t address);
	DLLEXPORT VOID WINAPI SearchForText(DWORD processId, LPCWSTR text, INT codepage);
	DLLEXPORT VOID WINAPI AddClipboardThread(HWND handle);
	DLLEXPORT VOID WINAPI SearchForHooks(DWORD processId, SearchParam* sp, FindHooks findhooks);
}