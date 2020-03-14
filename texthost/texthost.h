#pragma once
#include "pch.h"

#define DLLEXPORT extern "C" __declspec(dllexport)

typedef void(__stdcall* CallbackFunc)(DWORD processid);
typedef void(__stdcall* OnCreateThreadFunc)(int64_t thread_id,DWORD processId,uint64_t addr,uint64_t context,uint64_t subcontext,LPCWSTR name,LPCWSTR hookcode);
typedef void(__stdcall* OnRemoveThreadFunc)(int64_t thread_id);
typedef void(__stdcall* OnOutputFunc)(int64_t thread_id, LPCWSTR output);

namespace TextHost
{
	DLLEXPORT DWORD __stdcall TextHostInit(CallbackFunc connect, CallbackFunc disconnect, OnCreateThreadFunc create, OnRemoveThreadFunc remove, OnOutputFunc output);
	DLLEXPORT DWORD __stdcall InjectProcess(DWORD processId);
	DLLEXPORT DWORD __stdcall DetachProcess(DWORD processId);
	DLLEXPORT DWORD __stdcall InsertHook(DWORD processId, LPCWSTR command);
	DLLEXPORT DWORD __stdcall RemoveHook(DWORD processId, uint64_t address);
	DLLEXPORT BOOL __stdcall AddClipBoardThread(HWND handle);
}