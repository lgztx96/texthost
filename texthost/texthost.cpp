#include "pch.h"
#include "host.h"
#include "util.h"
#include "texthost.h"
#include <io.h>
#include <fcntl.h>


const wchar_t* ALREADY_INJECTED = L"Textractor: already injected";
const wchar_t* NEED_32_BIT = L"Textractor: architecture mismatch: only Textractor x86 can inject this process";
const wchar_t* NEED_64_BIT = L"Textractor: architecture mismatch: only Textractor x64 can inject this process";
const wchar_t* INVALID_CODEPAGE = L"Textractor: couldn't convert text (invalid codepage?)";
const wchar_t* INJECT_FAILED = L"Textractor: couldn't inject";
const wchar_t* CONSOLE = L"Console";
const wchar_t* CLIPBOARD = L"Clipboard";

namespace TextHost
{
	DLLEXPORT DWORD __stdcall TextHostInit(CallbackFunc connect,CallbackFunc disconnect,OnCreateThreadFunc create,OnRemoveThreadFunc remove,OnOutputFunc output)
	{
		Host::Start(connect,disconnect,
			[create](TextThread& thread) 
			{
				create(thread.handle,thread.tp.processId,thread.tp.addr,thread.tp.ctx,thread.tp.ctx2,thread.name.c_str(),Util::GenerateCode(thread.hp, thread.tp.processId).c_str());
			},
			[remove](TextThread& thread) 
			{
				remove(thread.handle);
			},
			[output](TextThread& thread, std::wstring& text) 
			{
				output(thread.handle, text.c_str());
				return false;
			});
		return 0;
	}

	DLLEXPORT DWORD __stdcall InjectProcess(DWORD processId)
	{
		Host::InjectProcess(processId);
		return 0;
	}

	DLLEXPORT DWORD __stdcall DetachProcess(DWORD processId)
	{
		Host::DetachProcess(processId);
		return 0;
	}

	DLLEXPORT DWORD __stdcall InsertHook(DWORD processId, LPCWSTR command)
	{
		auto hp = Util::ParseCode(command);
		Host::InsertHook(processId, hp.value());
		return 0;
	}

	DLLEXPORT DWORD __stdcall RemoveHook(DWORD processId, uint64_t address)
	{
		Host::RemoveHook(processId, address);
		return 0;
	}

	DLLEXPORT DWORD __stdcall AddClipBoardThread(HWND handle)
	{
		if (AddClipboardFormatListener(handle)==TRUE)
        Host::AddClipBoardThread(GetWindowThreadProcessId(handle, NULL));
		return 0;
	}
}

