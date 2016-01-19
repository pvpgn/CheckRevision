/*
*	See UNLICENSE file for license details
*	Refer to <http://unlicense.org/> if you have not received a copy of UNLICENSE
*/
#if _WIN32 || _WIN64
	#if _WIN64
		#error "64-bit DLLs can not be used in 32-bit programs"
	#endif
#endif
#include <Windows.h>

#define EXPORT extern "C" __declspec(dllexport)

EXPORT int __stdcall CheckRevision(LPCSTR lpszFileName1, LPCSTR lpszFileName2, LPCSTR lpszFileName3, int lpszValueString, unsigned long * lpdwVersion, unsigned long * lpdwChecksum, LPSTR lpExeInfoString);