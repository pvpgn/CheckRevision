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


extern "C" __declspec(dllexport) BOOL __stdcall CheckRevision(LPCSTR lpszFileName1, LPCSTR lpszFileName2, LPCSTR lpszFileName3, LPCSTR lpszValueString, DWORD *lpdwVersion, DWORD *lpdwChecksum, LPSTR lpszExeInfoString)
{
	if (lpszFileName1 == nullptr || lpszFileName2 == nullptr || lpszFileName3 == nullptr ||
		lpszValueString == nullptr || lpdwVersion == nullptr || lpdwChecksum == nullptr || lpszExeInfoString == nullptr)
	{
		return FALSE;
	}

	if (GetExeVer(lpszFileName1, lpdwVersion) == false)
	{
		return FALSE;
	}
	
#if _DEBUG
	if (GetChecksum(lpszFileName1, lpszFileName2, lpszFileName3, lpszValueString, lpdwChecksum) == false)
	{
		return FALSE;
	}
#else
	*lpdwChecksum = 0x0; //PvPGN can make assumptions of the client based on other data
#endif

	if (GetExeInfo(lpszFileName1, lpszExeInfoString) == false)
	{
		return FALSE;
	}

#if _DEBUG
	auto t = std::time(nullptr);
	auto tm = *std::localtime(&t);
	std::ofstream log("CheckRevision.log", std::ios::in | std::ios::ate);
	log << std::put_time(&tm, "%m/%d/%Y %H:%M:%S %p") << " — ExeInfoString: \"" << lpszExeInfoString << "\", Version: " << std::showbase << std::hex << lpdwVersion << ", Checksum: " << lpdwChecksum << std::endl;
#endif

	return TRUE;
}