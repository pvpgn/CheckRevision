/*
*	See UNLICENSE file for license details
*	Refer to <http://unlicense.org/> if you have not received a copy of UNLICENSE
*/


#include <Windows.h>


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD ul_reason_for_call, LPVOID)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	default:
		break;
	}

	return TRUE;
}

