#pragma once
#include "common.h"

namespace Extension
{
    //#define DLLEXPORT extern "C" __declspec(dllexport)
	bool  RemoveRepeatChar(int id,std::wstring& text);
	bool  RemoveRepeatPhrase(int id,std::wstring& text);
}