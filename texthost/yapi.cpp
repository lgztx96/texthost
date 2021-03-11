/*
  yapi -- Yet Another Process Injector / Your API
  A fusion library that reduce differences between x64, wow64 and x86 processes based on rewolf-wow64ext.

  Copyright (c) 2010-2018 <http://ez8.co> <orca.zhang@yahoo.com>
  This library is released under the MIT License.

  Please see LICENSE file or visit https://github.com/ez8-co/yapi for details.
*/

#include "pch.h"
#include "yapi.h"

namespace detail 
{
	BOOL Is64BitOS()
	{
		SYSTEM_INFO systemInfo = { 0 };
		GetNativeSystemInfo(&systemInfo);
		return systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
			|| systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64;
	}

	BOOL Is64BitProcess(HANDLE hProcess)
	{
		BOOL f64bitProc = FALSE;
		if (Is64BitOS())
		{
			f64bitProc = !(IsWow64Process(hProcess, &f64bitProc) && f64bitProc);
		}
		return f64bitProc;
	}
}

namespace yapi 
{
	DWORD64 WINAPI GetModuleHandle(HANDLE hProcess, const TCHAR* moduleName)
	{
		if (!moduleName) return 0;
		if (!hProcess) hProcess = detail::hCurProcess;

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
		if (hSnap == INVALID_HANDLE_VALUE) return 0;
		MODULEENTRY32 mod = { sizeof(mod) };
		if (Module32First(hSnap, &mod)) {
			do {
				if (!_tcsicmp(mod.szModule, moduleName)) {
					CloseHandle(hSnap);
					return (DWORD64)mod.hModule;
				}
			} while (Module32Next(hSnap, &mod));
		}
		CloseHandle(hSnap);
		return 0;
	}

	DWORD64 WINAPI GetProcAddress(HANDLE hProcess, DWORD64 hModule, const char* funcName)
	{
		if (!hModule || !funcName) return 0;
		if (!hProcess) hProcess = detail::hCurProcess;

		IMAGE_DOS_HEADER idh;
		NTSTATUS status = ReadProcessMemory(hProcess, (PVOID)hModule, (PVOID)&idh, sizeof(idh), NULL);
		if (!NT_SUCCESS(status)) return 0;

		IMAGE_NT_HEADERS32 inh;
		status = ReadProcessMemory(hProcess, (PVOID)(hModule + idh.e_lfanew), (PVOID)&inh, sizeof(inh), NULL);
		if (!NT_SUCCESS(status)) return 0;

		IMAGE_DATA_DIRECTORY& idd = inh.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!idd.VirtualAddress)return 0;

		IMAGE_EXPORT_DIRECTORY ied;
		status = ReadProcessMemory(hProcess, (PVOID)(hModule + idd.VirtualAddress), (PVOID)&ied, sizeof(ied), NULL);
		if (!NT_SUCCESS(status)) return 0;

		std::vector<DWORD> nameTable(ied.NumberOfNames);
		status = ReadProcessMemory(hProcess, (PVOID)(hModule + ied.AddressOfNames), (PVOID)&nameTable[0], sizeof(DWORD) * ied.NumberOfNames, NULL);
		if (!NT_SUCCESS(status)) return 0;

		for (DWORD i = 0; i < ied.NumberOfNames; ++i) {
			std::string func(strlen(funcName), 0);
			status = ReadProcessMemory(hProcess, (PVOID)(hModule + nameTable[i]), (PVOID)&func[0], strlen(funcName), NULL);
			if (!NT_SUCCESS(status)) continue;

			if (func == funcName) {
				WORD ord = 0;
				status = ReadProcessMemory(hProcess, (PVOID)(hModule + ied.AddressOfNameOrdinals + i * sizeof(WORD)), (PVOID)&ord, sizeof(WORD), NULL);
				if (!NT_SUCCESS(status)) continue;

				DWORD rva = 0;
				status = ReadProcessMemory(hProcess, (PVOID)(hModule + ied.AddressOfFunctions + ord * sizeof(DWORD)), (PVOID)&rva, sizeof(DWORD), NULL);
				if (!NT_SUCCESS(status)) continue;

				return hModule + rva;
			}
		}
		return 0;
	}

	DWORD64 WINAPI GetModuleHandle64(HANDLE hProcess, const TCHAR* moduleName)
	{
		if (!moduleName) return 0;
		if (!hProcess) hProcess = detail::hCurProcess;

#ifndef _WIN64
		if (!NtWow64QueryInformationProcess64 || !NtWow64ReadVirtualMemory64) return 0;
#endif

		PROCESS_BASIC_INFORMATION64 pbi = { 0 };
		const int ProcessBasicInformation = 0;
		NTSTATUS status = NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
		if (!NT_SUCCESS(status)) return 0;

		PEB64 peb;
		status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
		if (!NT_SUCCESS(status)) return 0;

		PEB_LDR_DATA64 ldr;
		status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)peb.Ldr, (PVOID)&ldr, sizeof(ldr), NULL);
		if (!NT_SUCCESS(status)) return 0;

		DWORD64 LastEntry = peb.Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);

		LDR_DATA_TABLE_ENTRY64 head;
		head.InLoadOrderLinks.Flink = ldr.InLoadOrderModuleList.Flink;
		do {
			status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)head.InLoadOrderLinks.Flink, (PVOID)&head, sizeof(head), NULL);
			if (!NT_SUCCESS(status)) continue;

			std::wstring modName((size_t)head.BaseDllName.MaximumLength, 0);
			status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)head.BaseDllName.Buffer, (PVOID)&modName[0], head.BaseDllName.MaximumLength, NULL);
			if (!NT_SUCCESS(status)) continue;

			if (!_tcsicmp(moduleName, _W2T(modName).c_str()))
				return head.DllBase;
		} while (head.InLoadOrderLinks.Flink != LastEntry);
		return 0;
	}

	DWORD64 WINAPI GetProcAddress64(HANDLE hProcess, DWORD64 hModule, const char* funcName)
	{
		if (!hModule || !funcName) return 0;
		if (!hProcess) hProcess = detail::hCurProcess;

#ifndef _WIN64
		if (!NtWow64ReadVirtualMemory64) return 0;
#endif

		IMAGE_DOS_HEADER idh;
		NTSTATUS status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)hModule, (PVOID)&idh, sizeof(idh), NULL);
		if (!NT_SUCCESS(status)) return 0;

		IMAGE_NT_HEADERS64 inh;
		status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)(hModule + idh.e_lfanew), (PVOID)&inh, sizeof(inh), NULL);
		if (!NT_SUCCESS(status)) return 0;

		IMAGE_DATA_DIRECTORY& idd = inh.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!idd.VirtualAddress)return 0;

		IMAGE_EXPORT_DIRECTORY ied;
		status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)(hModule + idd.VirtualAddress), (PVOID)&ied, sizeof(ied), NULL);
		if (!NT_SUCCESS(status)) return 0;

		std::vector<DWORD> nameTable(ied.NumberOfNames);
		status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)(hModule + ied.AddressOfNames), (PVOID)&nameTable[0], sizeof(DWORD) * ied.NumberOfNames, NULL);
		if (!NT_SUCCESS(status)) return 0;

		for (DWORD i = 0; i < ied.NumberOfNames; ++i) {
			std::string func(strlen(funcName), 0);
			status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)(hModule + nameTable[i]), (PVOID)&func[0], strlen(funcName), NULL);
			if (!NT_SUCCESS(status)) continue;

			if (func == funcName) {
				WORD ord = 0;
				status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)(hModule + ied.AddressOfNameOrdinals + i * sizeof(WORD)), (PVOID)&ord, sizeof(WORD), NULL);
				if (!NT_SUCCESS(status)) continue;

				DWORD rva = 0;
				status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)(hModule + ied.AddressOfFunctions + ord * sizeof(DWORD)), (PVOID)&rva, sizeof(DWORD), NULL);
				if (!NT_SUCCESS(status)) continue;

				return hModule + rva;
			}
		}
		return 0;
	}

	DWORD64 GetNtDll64()
	{
		static DWORD64 hNtdll64 = 0;
		if (hNtdll64) return hNtdll64;
		hNtdll64 = GetModuleHandle64(detail::hCurProcess, _T("ntdll.dll"));
		return hNtdll64;
	}

#ifndef _WIN64
	VOID WINAPI SetLastError64(DWORD64 status)
	{
		typedef ULONG(WINAPI* RTL_NTSTATUS_TO_DOS_ERROR)(NTSTATUS Status);
		typedef ULONG(WINAPI* RTL_SET_LAST_WIN32_ERROR)(NTSTATUS Status);

		static RTL_NTSTATUS_TO_DOS_ERROR RtlNtStatusToDosError = (RTL_NTSTATUS_TO_DOS_ERROR)GetProcAddress(detail::hNtDll, "RtlNtStatusToDosError");
		static RTL_SET_LAST_WIN32_ERROR RtlSetLastWin32Error = (RTL_SET_LAST_WIN32_ERROR)GetProcAddress(detail::hNtDll, "RtlSetLastWin32Error");

		if (RtlNtStatusToDosError && RtlSetLastWin32Error)
			RtlSetLastWin32Error(RtlNtStatusToDosError((DWORD)status));
	}

	SIZE_T WINAPI VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, SIZE_T dwLength)
	{
		static X64Call NtQueryVirtualMemory("NtQueryVirtualMemory");
		if (!NtQueryVirtualMemory) return 0;

		DWORD64 ret = 0;
		DWORD64 status = NtQueryVirtualMemory(hProcess, lpAddress, 0, lpBuffer, dwLength, &ret);
		if (!status) return (SIZE_T)ret;

		SetLastError64(ret);
		return FALSE;
	}

	DWORD64 WINAPI VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
	{
		static X64Call NtAllocateVirtualMemory("NtAllocateVirtualMemory");
		if (!NtAllocateVirtualMemory) return 0;

		DWORD64 tmpAddr = lpAddress;
		DWORD64 tmpSize = dwSize;
		DWORD64 ret = NtAllocateVirtualMemory(hProcess, &tmpAddr, 0, &tmpSize, flAllocationType, flProtect);
		if (!ret) return tmpAddr;

		SetLastError64(ret);
		return FALSE;
	}

	BOOL WINAPI VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType)
	{
		static X64Call NtFreeVirtualMemory("NtFreeVirtualMemory");
		if (!NtFreeVirtualMemory) return 0;

		DWORD64 tmpAddr = lpAddress;
		DWORD64 tmpSize = dwSize;
		DWORD64 ret = NtFreeVirtualMemory(hProcess, &tmpAddr, &tmpSize, dwFreeType);
		if (!ret) return TRUE;

		SetLastError64(ret);
		return FALSE;
	}

	BOOL WINAPI VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)
	{
		static X64Call NtProtectVirtualMemory("NtProtectVirtualMemory");
		if (!NtProtectVirtualMemory) return 0;

		DWORD64 tmpAddr = lpAddress;
		DWORD64 tmpSize = dwSize;
		DWORD64 ret = NtProtectVirtualMemory(hProcess, &tmpAddr, &tmpSize, flNewProtect, lpflOldProtect);
		if (!ret) return TRUE;

		SetLastError64(ret);
		return FALSE;
	}

	BOOL WINAPI ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
	{
		static X64Call NtReadVirtualMemory("NtReadVirtualMemory");
		if (!NtReadVirtualMemory) return 0;

		DWORD64 read = 0;
		DWORD64 ret = NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &read);
		if (!ret) {
			if (lpNumberOfBytesRead) *lpNumberOfBytesRead = (SIZE_T)read;
			return TRUE;
		}

		SetLastError64(ret);
		return FALSE;
	}

	BOOL WINAPI WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
	{
		static X64Call NtWriteVirtualMemory("NtWriteVirtualMemory");
		if (!NtWriteVirtualMemory) return 0;

		DWORD64 written = 0;
		DWORD64 ret = NtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &written);
		if (!ret) {
			if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = (SIZE_T)written;
			return TRUE;
		}

		SetLastError64(ret);
		return FALSE;
	}

	HANDLE WINAPI CreateRemoteThread64(HANDLE hProcess,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		SIZE_T dwStackSize,
		DWORD64 lpStartAddress,
		DWORD64 lpParameter,
		DWORD dwCreationFlags,
		LPDWORD lpThreadId)
	{
		static X64Call RtlCreateUserThread("RtlCreateUserThread");
		if (!RtlCreateUserThread) return 0;

		BOOLEAN createSuspended = dwCreationFlags & CREATE_SUSPENDED;
		ULONG stackSize = dwStackSize;
		DWORD64 handle = 0;
		DWORD64 status = RtlCreateUserThread(hProcess, lpThreadAttributes, createSuspended, 0, (dwCreationFlags & STACK_SIZE_PARAM_IS_A_RESERVATION) ? &stackSize : NULL, &stackSize, lpStartAddress, lpParameter, &handle, NULL);
		if (!status) return (HANDLE)handle;

		SetLastError64(status);
		return NULL;
	}
#endif
}




