/*
*	See UNLICENSE file for license details
*	Refer to <http://unlicense.org/> if you have not received a copy of UNLICENSE
*/
#if _WIN64
	#error "64-bit DLLs can not be used in 32-bit programs"
#endif
#include <Windows.h>

extern "C" __declspec(dllexport) BOOL __stdcall CheckRevision(LPCSTR lpszFileName1, LPCSTR lpszFileName2, LPCSTR lpszFileName3, LPCSTR lpszFormulaString, DWORD *lpdwVersion, DWORD *lpdwChecksum, LPSTR lpszExeInfoString);