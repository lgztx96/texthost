#pragma once

#include "pch.h"
#include "textthread.h"

namespace Host
{
	using ProcessEventHandler = std::function<void(DWORD)>;;
	using ThreadEventHandler = std::function<void(TextThread&)>;

	template <typename T>
	using HookEventHandler = std::function<void(T, std::wstring text)>;

	void Start(ProcessEventHandler Connect, ProcessEventHandler Disconnect, ThreadEventHandler Create, ThreadEventHandler Destroy, TextThread::OutputCallback Output);

	void InjectProcess(DWORD processId);
	void DetachProcess(DWORD processId);

	void InsertHookX86(DWORD processId, HookParamX86 hp);
	void InsertHookX64(DWORD processId, HookParamX64 hp);

	void RemoveHook(DWORD processId, uint64_t address);

	void FindHooksX86(DWORD processId, SearchParamX86 sp, HookEventHandler<HookParamX86> HookFound = {});
	void FindHooksX64(DWORD processId, SearchParamX64 sp, HookEventHandler<HookParamX64> HookFound = {});

	TextThread* GetThread(int64_t handle);
	TextThread& GetThread(ThreadParam tp);

	void AddConsoleOutput(std::wstring text);
	void AddClipboardThread(DWORD thread_id);

	inline int defaultCodepage = SHIFT_JIS;

	constexpr ThreadParam console{ 0, -1LL, -1LL, -1LL }, clipboard{ 0, 0, -1LL, -1LL };
}




