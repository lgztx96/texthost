#pragma once

#include "pch.h"
#include "const.h"

class WinMutex // Like CMutex but works with scoped_lock
{
public:
	WinMutex(std::wstring name = L"", LPSECURITY_ATTRIBUTES sa = nullptr) : m(CreateMutexW(sa, FALSE, name.empty() ? NULL : name.c_str())) {}
	void lock() { if (m) WaitForSingleObject(m, INFINITE); }
	void unlock() { if (m) ReleaseMutex(m); }

private:
	AutoHandle<> m;
};

inline SECURITY_ATTRIBUTES allAccess = std::invoke([] // allows non-admin processes to access kernel objects made by admin processes
	{
		static SECURITY_DESCRIPTOR sd = {};
		InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
		return SECURITY_ATTRIBUTES{ sizeof(SECURITY_ATTRIBUTES), &sd, FALSE };
	});

struct HookBaseInfo 
{
	DWORD type; // flags
	UINT codepage; // text encoding
	std::wstring HookCode;
	char name[HOOK_NAME_SIZE];
};

struct HookParamX86
{
	uint64_t address; // absolute or relative address
	int offset, // offset of the data in the memory
		index, // deref_offset1
		split, // offset of the split character
		split_index, // deref_offset2
		null_length;

	wchar_t module[MAX_MODULE_SIZE];

	char function[MAX_MODULE_SIZE];
	DWORD type; // flags
	UINT codepage; // text encoding
	short length_offset; // index of the string length
	uint32_t padding; // padding before string
	DWORD user_value; // 7/20/2014: jichi additional parameters for PSP games

	uint32_t text_fun;
	uint32_t filter_fun;
	uint32_t hook_fun;
	uint32_t length_fun;
	char name[HOOK_NAME_SIZE];
};


struct HookParamX64
{
	uint64_t address; // absolute or relative address
	int offset, // offset of the data in the memory
		index, // deref_offset1
		split, // offset of the split character
		split_index, // deref_offset2
		null_length;

	wchar_t module[MAX_MODULE_SIZE];

	char function[MAX_MODULE_SIZE];
	DWORD type; // flags
	UINT codepage; // text encoding
	short length_offset; // index of the string length
	uint64_t padding; // padding before string
	DWORD user_value; // 7/20/2014: jichi additional parameters for PSP games

	uint64_t text_fun;
	uint64_t filter_fun;
	uint64_t hook_fun;
	uint64_t length_fun;
	char name[HOOK_NAME_SIZE];
};

struct ThreadParam
{
	bool operator==(ThreadParam other) const { return processId == other.processId && addr == other.addr && ctx == other.ctx && ctx2 == other.ctx2; }
	DWORD processId;
	uint64_t addr;
	uint64_t ctx; // The context of the hook: by default the first value on stack, usually the return address
	uint64_t ctx2;  // The subcontext of the hook: 0 by default, generated in a method specific to the hook
};

struct SearchParamX86
{
	BYTE pattern[PATTERN_SIZE] = { 0x55, 0x8b, 0xec, 0x89 }; // pattern in memory to search for
	int length = 3, // length of pattern (zero means this SearchParam is invalid and the default should be used)
		offset = 0, // offset from start of pattern to add hook
		searchTime = 30000, // ms
		maxRecords = 100000,
		codepage = SHIFT_JIS;
	uint32_t padding = 0, // same as hook param padding
		minAddress = 0, maxAddress = (uintptr_t)-1; // hook all functions between these addresses (used only if both modules empty)
	wchar_t boundaryModule[MAX_MODULE_SIZE] = {}; // hook all functions within this module (middle priority)
	wchar_t exportModule[MAX_MODULE_SIZE] = {}; // hook the exports of this module (highest priority)
	wchar_t text[PATTERN_SIZE] = {}; // text to search for
	uint32_t hookPostProcessor = 0;
};

struct SearchParamX64
{
	BYTE pattern[PATTERN_SIZE] = { 0xcc, 0xcc, 0x48, 0x89 }; // pattern in memory to search for
	int length = 4, // length of pattern (zero means this SearchParam is invalid and the default should be used)
		offset = 2, // offset from start of pattern to add hook
		searchTime = 30000, // ms
		maxRecords = 100000,
		codepage = SHIFT_JIS;
	uint64_t padding = 0, // same as hook param padding
		minAddress = 0, maxAddress = (uintptr_t)-1; // hook all functions between these addresses (used only if both modules empty)
	wchar_t boundaryModule[MAX_MODULE_SIZE] = {}; // hook all functions within this module (middle priority)
	wchar_t exportModule[MAX_MODULE_SIZE] = {}; // hook the exports of this module (highest priority)
	wchar_t text[PATTERN_SIZE] = {}; // text to search for
	uint64_t hookPostProcessor = 0;
};

template<typename T>
concept HookParam = std::same_as<HookParamX86, T> || std::same_as<HookParamX64, T>;

template<typename T>
concept SearchParam = std::same_as<SearchParamX86, T> || std::same_as<SearchParamX64, T>;

template <HookParam T>
struct InsertHookCmd // From host
{
	InsertHookCmd(T hp) : hp(hp) {}
	HostCommandType command = HOST_COMMAND_NEW_HOOK;
	T hp;
};

struct RemoveHookCmd // From host
{
	RemoveHookCmd(uint64_t address) : address(address) {}
	HostCommandType command = HOST_COMMAND_REMOVE_HOOK;
	uint64_t address;
};

template <SearchParam T>
struct FindHookCmd // From host
{
	FindHookCmd(T sp) : sp(sp) {}
	HostCommandType command = HOST_COMMAND_FIND_HOOK;
	T sp;
};

struct ConsoleOutputNotif // From dll
{
	ConsoleOutputNotif(std::string message = "") { strncpy_s(this->message, message.c_str(), MESSAGE_SIZE - 1); }
	HostNotificationType command = HOST_NOTIFICATION_TEXT;
	char message[MESSAGE_SIZE] = {};
};

template <HookParam T>
struct HookFoundNotif // From dll
{
	HookFoundNotif(T hp, wchar_t* text) : hp(hp) { wcsncpy_s(this->text, text, MESSAGE_SIZE - 1); }
	HostNotificationType command = HOST_NOTIFICATION_FOUND_HOOK;
	T hp;
	wchar_t text[MESSAGE_SIZE] = {}; // though type is wchar_t, may not be encoded in UTF-16 (it's just convenient to use wcs* functions)
};

struct HookRemovedNotif // From dll
{
	HookRemovedNotif(uint64_t address) : address(address) {};
	HostNotificationType command = HOST_NOTIFICATION_RMVHOOK;
	uint64_t address;
};
