/*
*	See UNLICENSE file for license details
*	Refer to <http://unlicense.org/> if you have not received a copy of UNLICENSE
*/
#if _DEBUG
#include <ctime>
#include <fstream>
#include <iomanip>
#endif
#include <Windows.h>

#include "CheckRevision.h"
#include "util.h"


extern "C" __declspec(dllexport) BOOL __stdcall CheckRevision(LPCSTR lpszFileName1, LPCSTR lpszFileName2, LPCSTR lpszFileName3, LPCSTR lpszFormulaString, DWORD *lpdwVersion, DWORD *lpdwChecksum, LPSTR lpszExeInfoString)
{
	if (lpszFileName1 == nullptr || lpszFileName2 == nullptr || lpszFileName3 == nullptr ||
		lpszFormulaString == nullptr || lpdwVersion == nullptr || lpdwChecksum == nullptr || lpszExeInfoString == nullptr)
		return FALSE;

	if (GetExeVer(lpszFileName1, lpdwVersion) == false)
		return FALSE;
	
	if (GetChecksum(lpszFormulaString, { lpszFileName1, lpszFileName2, lpszFileName3 }, lpdwChecksum) == false)
		return FALSE;

	if (GetExeInfo(lpszFileName1, lpszExeInfoString) == false)
		return FALSE;

#if _DEBUG
	auto t = std::time(nullptr);
	auto tm = *std::localtime(&t);
	std::ofstream log("CheckRevision.log", std::ios::in | std::ios::ate); //will only write if file already exists
	log << std::put_time(&tm, "%m/%d/%Y %H:%M:%S %p") << "\nExeInfoString: " << lpszExeInfoString << "\nVersion: " << std::showbase << std::hex << *lpdwVersion << "\nChecksum: " << *lpdwChecksum << '\n' << std::endl;
#endif

	return TRUE;
}