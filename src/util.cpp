/*-
* Copyright (c) 2007 Ryan Kwolek
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without modification, are
* permitted provided that the following conditions are met:
*  1. Redistributions of source code must retain the above copyright notice, this list of
*     conditions and the following disclaimer.
*  2. Redistributions in binary form must reproduce the above copyright notice, this list
*     of conditions and the following disclaimer in the documentation and/or other materials
*     provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED
* WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
* FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR
* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
* ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
* ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
//https://github.com/kwolekr/horizon/blob/master/src/checkrevision.cpp

/*
*	Modifications by xboi209 <xboi209@gmail.com>
*/

#include <cassert> //assert()
#include <cctype> //std::isalpha(), std::toupper()
#include <cstdio> //std::sprintf()
#include <cstdlib> //std::atol()
#include <cstring> //std::strchr()
#include <ctime> //std::gmtime()
#include <Windows.h>
#include <sys/types.h> //_stat64
#include <sys/stat.h> //^
//non-standard header: https://msdn.microsoft.com/en-us/library/hh874694(v=vs.140).aspx
#include <filesystem> //std::tr2::sys

#include "util.h"

bool GetExeInfo(LPCSTR lpszFileName, char *lpExeInfoString)
{
	std::tr2::sys::path file = lpszFileName;
	VS_FIXEDFILEINFO *ffi;
	DWORD dwSize = GetFileVersionInfoSize(file.string().c_str(), nullptr);
	LPBYTE lpbBuffer = (LPBYTE)VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	struct _stat64 buf;
	struct tm* filetime;
	int statret = _stat64(lpszFileName, &buf);

	assert(statret != EINVAL); //invalid parameter
	if (statret == -1)
		return false;
	if (lpbBuffer == NULL)
		return false;
	if (GetFileVersionInfo(file.string().c_str(), NULL, dwSize, lpbBuffer) == FALSE)
		return false;
	if (VerQueryValue(lpbBuffer, "\\", (LPVOID *)&ffi, (PUINT)&dwSize) == FALSE)
		return false;

	VirtualFree(lpbBuffer, 0lu, MEM_RELEASE);

	//st_mtime is the time of last modification of file.
	filetime = std::gmtime(&(buf.st_mtime));

	/*
	*	The data that should be used for EXE Information should be separated by one space, in the format of:
	*	EXE Name (like war3.exe)
	*	Last Modified Date (like 08/16/09)
	*	Last Modified Time (like 19:21:59)
	*	Filesize in bytes (like 471040)
	*	example: war3.exe 08/16/09 19:21:59 471040
	*/
	std::sprintf(lpExeInfoString, "%s %02u/%02u/%02u %02u:%02u:%02u %lu",
		file.filename().string().c_str(), filetime->tm_mon + 1, filetime->tm_mday, filetime->tm_year % 100, filetime->tm_hour, filetime->tm_min, filetime->tm_sec, buf.st_size);
	
	return true;
}

bool GetExeVer(LPCSTR lpszFileName, unsigned long * lpdwVersion)
{
	VS_FIXEDFILEINFO *ffi;

	DWORD dwSizeOfFileInfoVer = GetFileVersionInfoSize(lpszFileName, nullptr);
	if (!dwSizeOfFileInfoVer)
		return false;

	LPVOID lpbBuffer = VirtualAlloc(NULL, dwSizeOfFileInfoVer, MEM_COMMIT, PAGE_READWRITE);
	if (!lpbBuffer)
		return false;

	if (!GetFileVersionInfo(lpszFileName, NULL, dwSizeOfFileInfoVer, lpbBuffer))
		return false;

	if (!VerQueryValue(lpbBuffer, "\\", (LPVOID*)&ffi, (PUINT)&dwSizeOfFileInfoVer))
		return false;

	*lpdwVersion = ((HIWORD(ffi->dwProductVersionMS) & 0xFF) << 24) |
		((LOWORD(ffi->dwProductVersionMS) & 0xFF) << 16) |
		((HIWORD(ffi->dwProductVersionLS) & 0xFF) << 8) |
		(LOWORD(ffi->dwProductVersionLS) & 0xFF);

	VirtualFree(lpbBuffer, 0lu, MEM_RELEASE);

	return true;
}

//faulty code
bool GetChecksum(LPCSTR lpszFileName1, LPCSTR lpszFileName2, LPCSTR lpszFileName3, int lpszValueString, unsigned long * lpdwChecksum)
{
	//Blizzard only has 7 versions of ver-ix86-#.dll(first version begins on 0)
	static_assert(VERIX86VERSION > 0 && VERIX86VERSION < 7, "VERIX86VERSION must be between 0 and 6");

	LPSTR lpszFileNames[3];
	int nVariable, nHashOperations, nVariable1[16], nVariable2[16], nVariable3[16];
	DWORD dwVariables[4], *lpdwBuffer, dwTotalSize, dwSize;
	char cOperations[16];//Should it be 16 bytes? 
	HANDLE hFile, hFileMapping;
	FILETIME ft;
	SYSTEMTIME st;
	const DWORD dwMpqKey = dwMpqChecksumKeys[VERIX86VERSION];

	lpszFileNames[0] = (LPSTR)lpszFileName1;
	lpszFileNames[1] = (LPSTR)lpszFileName2;
	lpszFileNames[2] = (LPSTR)lpszFileName3;
	char *s = (char *)lpszValueString;

	while (*s != '\0')
	{
		if (std::isalpha(*s))
			nVariable = (int)(std::toupper(*s) - 'A');
		else
		{
			nHashOperations = (int)(*s - '0');
			s = std::strchr(s, ' ');
			if (s == nullptr)
				return false;
			s++;
			break;
		}

		if (*(++s) == '=')
			s++;

		dwVariables[nVariable] = std::atol(s);

		s = std::strchr(s, ' ');
		if (s == nullptr)
			return false;

		s++;
	}

	for (auto i = 0; i < nHashOperations; i++)
	{
		if (!std::isalpha(*s))
			return false;

		nVariable1[i] = (int)(std::toupper(*s) - 'A');

		if (*(++s) == '=')
			s++;

		if (std::toupper(*s) == 'S')
			nVariable2[i] = 3;
		else
			nVariable2[i] = (int)(std::toupper(*s) - 'A');

		cOperations[i] = *(++s);

		s++;

		if (std::toupper(*s) == 'S')
			nVariable3[i] = 3;
		else
			nVariable3[i] = (int)(std::toupper(*s) - 'A');

		s = std::strchr(s, ' ');
		if (s == NULL)
			break;

		s++;
	}

	dwVariables[0] ^= dwMpqKey;
	for (auto i = 0; i < 3; i++)
	{
		if (lpszFileNames[i][0] == '\0')
			continue;

		hFile = CreateFile(lpszFileNames[i],
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hFile == (HANDLE)INVALID_HANDLE_VALUE)
			return false;

		hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hFileMapping == NULL)
		{
			CloseHandle(hFile);
			return false;
		}

		lpdwBuffer = (LPDWORD)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if (lpdwBuffer == NULL)
		{
			CloseHandle(hFileMapping);
			CloseHandle(hFile);
			return false;
		}

		if (i == 0)
		{
			GetFileTime(hFile, &ft, NULL, NULL);
			FileTimeToSystemTime(&ft, &st);
			dwTotalSize = GetFileSize(hFile, NULL);
		}
		dwSize = (GetFileSize(hFile, NULL) / 1024lu) * 1024lu;
		for (DWORD j = 0; j < (dwSize / 4lu); j++)
		{
			dwVariables[3] = lpdwBuffer[j];
			for (auto k = 0; k < nHashOperations; k++)
			{
				switch (cOperations[k])
				{
				case '+':
					dwVariables[nVariable1[k]] = dwVariables[nVariable2[k]] +
						dwVariables[nVariable3[k]];
					break;
				case '-':
					dwVariables[nVariable1[k]] = dwVariables[nVariable2[k]] -
						dwVariables[nVariable3[k]];
					break;
				case '^':
					dwVariables[nVariable1[k]] = dwVariables[nVariable2[k]] ^
						dwVariables[nVariable3[k]];
					break;
				default:
					return FALSE;
				}
			}
		}
		UnmapViewOfFile(lpdwBuffer);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
	}

	*lpdwChecksum = dwVariables[2];
	return true;
}