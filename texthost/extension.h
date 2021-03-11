#pragma once

#include "pch.h"

namespace Extension
{
	void RemoveRepeatChar(std::wstring& text);
	void RemoveRepeatPhrase(std::wstring& text);

	std::wstring& trim(std::wstring& str);
	std::wstring& trim_start(std::wstring& str);
	std::wstring& trim_end(std::wstring& str);
}