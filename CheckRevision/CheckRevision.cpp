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


EXPORT BOOL __stdcall CheckRevision(LPCSTR lpszFileName1, LPCSTR lpszFileName2, LPCSTR lpszFileName3, int lpszValueString, unsigned long * lpdwVersion, unsigned long * lpdwChecksum, LPSTR lpExeInfoString)
{
	if (lpszFileName1 == nullptr || lpszFileName2 == nullptr || lpszFileName3 == nullptr || lpdwVersion == nullptr || lpdwChecksum == nullptr || lpExeInfoString == nullptr)
		return FALSE;

	if (!GetExeVer(lpszFileName1, lpdwVersion))
		return FALSE;
	
#if _DEBUG
	if (!GetChecksum(lpszFileName1, lpszFileName2, lpszFileName3, lpszValueString, lpdwChecksum))
		return FALSE;
#else
	*lpdwChecksum = 0x0; //PvPGN can make assumptions of the client based on other data
#endif

	if (!GetExeInfo(lpszFileName1, lpExeInfoString))
		return FALSE;

	// Custom code here

#if _DEBUG
	auto t = std::time(nullptr);
	auto tm = *std::localtime(&t);
	std::ofstream log;
	log.open("CheckRevision.log", std::ios::in | std::ios::ate);
	log << std::put_time(&tm, "%m/%d/%Y %H:%M:%S %p") << " — ExeInfoString: \"" << lpExeInfoString << "\", Version: 0x" << lpdwVersion << ", Checksum: 0x" << lpdwChecksum << std::endl;
	log.close();
#endif

	return TRUE;
}