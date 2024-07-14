#pragma once

#ifndef __wtypes_h__
#include <wtypes.h>
#endif

#ifndef __WINDEF_
#include <windef.h>
#endif

#include <TlHelp32.h>
#include "PEstruct.h"


#include <string>



HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char* sProcName);
LPCWSTR charToLPCWSTR(const char* charString);
LPSTR charToLPSTR(const char* str);
LPWSTR charToLPWSTR(const char* charString);
BSTR ConvertCharToBSTR(const char* charArray);
std::string WStringToString(const std::wstring& wstr);
HMODULE getNTDLL();
BOOL SetPrivilege(LPCWSTR privilege);