#include "pch.h"
#include "util.h"
#include "wow64ext.h"

//see https://blog.poxiao.me/p/wow64-process-inject-dll-into-x64-process/

template<typename Res, typename Deleter>
class ScopeResource {
    Res res;
    Deleter deleter;
    ScopeResource(const ScopeResource&) {}
public:
    Res get() const {
        return this->res;
    }
    ScopeResource(Res res, Deleter deleter) : res(res), deleter(deleter) {}
    ~ScopeResource() {
        this->deleter(this->res);
    }
};

InjectResult Wow64InjectWin64(DWORD dwProcessId, const std::wstring& filename)
{
    DWORD dwDesiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    auto closeProcessHandle = [](HANDLE hProcess) {
        if (hProcess != NULL) CloseHandle(hProcess);
    };
    ScopeResource<HANDLE, decltype(closeProcessHandle)> targetProcessHandle(OpenProcess(dwDesiredAccess, FALSE, dwProcessId), closeProcessHandle);
    if (targetProcessHandle.get() == NULL) {
        return InjectResult::Error_OpenProcess;
    }
    unsigned char injectCode[] = {
        0x48, 0x89, 0x4c, 0x24, 0x08,                               // mov       qword ptr [rsp+8],rcx
        0x57,                                                       // push      rdi
        0x48, 0x83, 0xec, 0x20,                                     // sub       rsp,20h
        0x48, 0x8b, 0xfc,                                           // mov       rdi,rsp
        0xb9, 0x08, 0x00, 0x00, 0x00,                               // mov       ecx,8
        0xb8, 0xcc, 0xcc, 0xcc, 0xcc,                               // mov       eac,0CCCCCCCCh
        0xf3, 0xab,                                                 // rep stos  dword ptr [rdi]
        0x48, 0x8b, 0x4c, 0x24, 0x30,                               // mov       rcx,qword ptr [__formal]
        0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       r9,0
        0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       r8,0
        0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rdx,0
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0
        0xff, 0xd0,                                                 // call      rax
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0
        0xff, 0xd0                                                  // call      rax
    };

    size_t parametersMemSize = sizeof(DWORD64) + sizeof(_UNICODE_STRING_T<DWORD64>) + (filename.size() + 1) * sizeof(wchar_t);
    auto freeInjectCodeMem = [&targetProcessHandle, &injectCode](DWORD64 address) {
        if (address != 0) VirtualFreeEx64(targetProcessHandle.get(), address, sizeof(injectCode), MEM_COMMIT | MEM_RESERVE);
    };
    ScopeResource<DWORD64, decltype(freeInjectCodeMem)> injectCodeMem(VirtualAllocEx64(targetProcessHandle.get(), NULL, sizeof(injectCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE), freeInjectCodeMem);
    auto freeParametersMem = [&targetProcessHandle, parametersMemSize](DWORD64 address) {
        if (address != 0) VirtualFreeEx64(targetProcessHandle.get(), address, parametersMemSize, MEM_COMMIT | MEM_RESERVE);
    };
    ScopeResource<DWORD64, decltype(freeParametersMem)> parametersMem(VirtualAllocEx64(targetProcessHandle.get(), NULL, parametersMemSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), freeParametersMem);
    if (injectCodeMem.get() == 0 || parametersMem.get() == 0) {
        return InjectResult::Error_VirtualAllocEx;
    }
    DWORD64 ntdll64 = GetModuleHandle64(L"ntdll.dll");
    DWORD64 ntdll_LdrLoadDll = GetProcAddress64(ntdll64, "LdrLoadDll");
    DWORD64 ntdll_RtlExitUserThread = GetProcAddress64(ntdll64, "RtlExitUserThread");
    DWORD64 ntdll_RtlCreateUserThread = GetProcAddress64(ntdll64, "RtlCreateUserThread");
    if (ntdll_LdrLoadDll == 0 || ntdll_RtlExitUserThread == 0 || ntdll_RtlCreateUserThread == 0) {
        return InjectResult::Error_GetProcAddress;
    }
    std::unique_ptr<unsigned char[]> parameters(new unsigned char[parametersMemSize]);
    std::memset(parameters.get(), 0, parametersMemSize);
    _UNICODE_STRING_T<DWORD64>* upath = reinterpret_cast<_UNICODE_STRING_T<DWORD64>*>(parameters.get() + sizeof(DWORD64));
    upath->Length = filename.size() * sizeof(wchar_t);
    upath->MaximumLength = (filename.size() + 1) * sizeof(wchar_t);
    wchar_t* path = reinterpret_cast<wchar_t*>(parameters.get() + sizeof(DWORD64) + sizeof(_UNICODE_STRING_T<DWORD64>));
    std::copy(filename.begin(), filename.end(), path);
    upath->Buffer = parametersMem.get() + sizeof(DWORD64) + sizeof(_UNICODE_STRING_T<DWORD64>);

    union {
        DWORD64 from;
        unsigned char to[8];
    } cvt;

    // r9
    cvt.from = parametersMem.get();
    std::memcpy(injectCode + 32, cvt.to, sizeof(cvt.to));

    // r8
    cvt.from = parametersMem.get() + sizeof(DWORD64);
    std::memcpy(injectCode + 42, cvt.to, sizeof(cvt.to));

    // rax = LdrLoadDll
    cvt.from = ntdll_LdrLoadDll;
    std::memcpy(injectCode + 72, cvt.to, sizeof(cvt.to));

    // rax = RtlExitUserThread
    cvt.from = ntdll_RtlExitUserThread;
    std::memcpy(injectCode + 94, cvt.to, sizeof(cvt.to));

    if (FALSE == WriteProcessMemory64(targetProcessHandle.get(), injectCodeMem.get(), injectCode, sizeof(injectCode), NULL)
        || FALSE == WriteProcessMemory64(targetProcessHandle.get(), parametersMem.get(), parameters.get(), parametersMemSize, NULL)) {
        return InjectResult::Error_WriteProcessMemory;
    }

    DWORD64 hRemoteThread = 0;
    struct {
        DWORD64 UniqueProcess;
        DWORD64 UniqueThread;
    } client_id;

    X64Call(ntdll_RtlCreateUserThread, 10,
        (DWORD64)targetProcessHandle.get(), // ProcessHandle
        (DWORD64)NULL,                      // SecurityDescriptor
        (DWORD64)FALSE,                     // CreateSuspended
        (DWORD64)0,                         // StackZeroBits
        (DWORD64)NULL,                      // StackReserved
        (DWORD64)NULL,                      // StackCommit
        injectCodeMem.get(),                // StartAddress
        (DWORD64)NULL,                      // StartParameter
        (DWORD64)&hRemoteThread,            // ThreadHandle
        (DWORD64)&client_id);               // ClientID
    if (hRemoteThread != 0) {
        CloseHandle((HANDLE)hRemoteThread);
        return InjectResult::OK;
    }
    return InjectResult::Error_CreateRemoteThread;
}

BOOL Is64BitOS() {
#if defined(_WIN64)
    return TRUE; // 64-bit programs run only on Win64
#elif defined(_WIN32)
        // 32-bit programs run on both 32-bit and 64-bit Windows
        BOOL f64bitOS = FALSE;
        HMODULE hModule = GetModuleHandle(TEXT("kernel32"));
        FARPROC fnIsWow64Process = GetProcAddress(hModule, "IsWow64Process");
    return (fnIsWow64Process != NULL 
        && (IsWow64Process(GetCurrentProcess(), &f64bitOS) 
            && f64bitOS));
#else
    return FALSE; // 64-bit Windows does not support Win16
#endif
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