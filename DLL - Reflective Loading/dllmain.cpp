// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH:
		WCHAR text[64];
		StringCchPrintf(text, _countof(text), L"Injected into process %u!", GetCurrentProcessId());
		MessageBox(nullptr, text, L"Injected DLL", MB_OK);
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

