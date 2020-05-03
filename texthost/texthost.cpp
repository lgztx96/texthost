#include "pch.h"
#include "host.h"
#include "util.h"
#include "texthost.h"
#include "extension.h"
#include <io.h>
#include <fcntl.h>

//const wchar_t* ALREADY_INJECTED = L"Textractor: already injected";
//const wchar_t* NEED_32_BIT = L"Textractor: architecture mismatch: only Textractor x86 can inject this process";
//const wchar_t* NEED_64_BIT = L"Textractor: architecture mismatch: only Textractor x64 can inject this process";
//const wchar_t* INVALID_CODEPAGE = L"Textractor: couldn't convert text (invalid codepage?)";
//const wchar_t* INJECT_FAILED = L"Textractor: couldn't inject";
//const wchar_t* INVALID_CODE = L"Textractor: invalid code";
//const wchar_t* INVALID_PROCESS = L"Textractor: invalid process";
//const wchar_t* INITIALIZED = L"Textractor: initialization completed";
//const wchar_t* CONSOLE = L"Console";
//const wchar_t* CLIPBOARD = L"Clipboard";

const wchar_t* ALREADY_INJECTED = L"Textractor: 已经注入";
const wchar_t* NEED_32_BIT = L"Textractor: 架构不匹配: 请尝试使用32位版本的Textractor";
const wchar_t* NEED_64_BIT = L"Textractor: 架构不匹配: 请尝试使用64位版本的Textractor";
const wchar_t* INVALID_CODEPAGE = L"Textractor: 无法转换文本 (无效的代码页?)";
const wchar_t* INJECT_FAILED = L"Textractor: 无法注入";
const wchar_t* INVALID_CODE = L"Textractor: 无效特殊码";
const wchar_t* INVALID_PROCESS = L"Textractor: 无效进程";
const wchar_t* INITIALIZED = L"Textractor: 初始化完成";
const wchar_t* CONSOLE = L"控制台";
const wchar_t* CLIPBOARD = L"剪贴板";

namespace TextHost
{
	DLLEXPORT DWORD WINAPI TextHostInit( ProcessEvent connect,
		                                 ProcessEvent disconnect,
		                                 OnCreateThread create,
		                                 OnRemoveThread remove,
		                                 OutputText output
	                                    )
	{
		auto createthread = [create](TextThread& thread)
		{
			create(thread.handle, 
				thread.tp.processId, 
				thread.tp.addr, 
				thread.tp.ctx, 
				thread.tp.ctx2, 
				thread.name.c_str(), 
				Util::GenerateCode(thread.hp, thread.tp.processId).c_str());
		};
		auto removethread = [remove](TextThread& thread)
		{
			remove(thread.handle);
		};
		auto outputtext = [output](TextThread& thread, std::wstring& text)
		{
			Extension::RemoveRepeatChar(thread.handle,text);
			Extension::RemoveRepeatPhrase(thread.handle,text);
			output(thread.handle, text.c_str());
			return false;
		};

		Host::Start(connect,disconnect,createthread,removethread,outputtext);
		Host::AddConsoleOutput(INITIALIZED);
		return 0;
	}

	DLLEXPORT DWORD WINAPI InjectProcess(DWORD processId)
	{
		try { Host::InjectProcess(processId); }
		catch (std::out_of_range) {}		
		return 0;
	}

	DLLEXPORT DWORD WINAPI DetachProcess(DWORD processId)
	{
		try { Host::DetachProcess(processId); }
		catch (std::out_of_range)
		{ Host::AddConsoleOutput(INVALID_PROCESS); }
		return 0;
	}

	DLLEXPORT DWORD WINAPI InsertHook(DWORD processId, LPCWSTR command)
	{
		if(auto hp = Util::ParseCode(command))
		try {Host::InsertHook(processId, hp.value());}catch(std::out_of_range){}
		else { Host::AddConsoleOutput(INVALID_CODE); }
		return 0;
	}
	
	DLLEXPORT DWORD WINAPI RemoveHook(DWORD processId, uint64_t address)
	{
		try { Host::RemoveHook(processId, address); }
		catch (std::out_of_range) {}
		return 0;
	}

	DLLEXPORT DWORD WINAPI FindHooks(DWORD processId,LPCWSTR text, int codepage)
	{
		SearchParam sp = {};
		wcsncpy_s(sp.text, text, PATTERN_SIZE - 1);
		sp.codepage = codepage;
		try { Host::FindHooks(processId, sp); }
		catch (std::out_of_range) {}
		return 0;
	}

	DLLEXPORT DWORD WINAPI AddClipboardThread(HWND handle)
	{
		if (AddClipboardFormatListener(handle) == TRUE)
			Host::AddClipboardThread(GetWindowThreadProcessId(handle, NULL));
		return 0;
	}
}

