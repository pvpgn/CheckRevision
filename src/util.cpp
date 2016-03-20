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
//https://github.com/kwolekr/phyros/blob/master/src/crypto/checkrevision.c

/*
*	Modifications by xboi209 <xboi209@gmail.com>
*/


#include "checkrevision.h"
#include "util.h"

#include <array>
#include <cassert>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>

#include <Windows.h>
#include <sys/types.h>
#include <sys/stat.h>


bool GetExeInfo(const std::string& lpszFileName, char *lpszExeInfoString)
{
	struct _stat buf = {};
	int statret = _stat(lpszFileName.c_str(), &buf);
	assert(statret != EINVAL); //invalid parameter
	if (statret == -1)
		return false;

	//st_mtime is the time of last modification of file.
	struct tm *filetime = std::gmtime(&buf.st_mtime);
	if (filetime == nullptr)
		return false;

	/*
	*	The data that should be used for EXE Information should be separated by one space, in the format of:
	*	EXE Name (like war3.exe)
	*	Last Modified Date (like 08/16/09)
	*	Last Modified Time (like 19:21:59)
	*	Filesize in bytes (like 471040)
	*	example: war3.exe 08/16/09 19:21:59 471040
	*/
	std::sprintf(lpszExeInfoString, "%s %02d/%02d/%02d %02d:%02d:%02d %ld",
		lpszFileName, filetime->tm_mon + 1, filetime->tm_mday, filetime->tm_year % 100, 
		filetime->tm_hour, filetime->tm_min, filetime->tm_sec, buf.st_size);
	
	return true;
}


/*******************************************************************************************************************
********************************************************************************************************************
********************************************************************************************************************
*******************************************************************************************************************/


class VirtualFreeDeleter
{
public:
	using pointer = LPVOID;

	void operator()(LPVOID lpAddress) const
	{
		VirtualFree(lpAddress, 0, MEM_RELEASE);
	}
};


bool GetExeVer(const std::string& lpszFileName, DWORD *lpdwVersion)
{
	DWORD dwSizeOfFileInfoVer = GetFileVersionInfoSizeA(lpszFileName.c_str(), nullptr);
	if (dwSizeOfFileInfoVer == 0)
		return false;

	std::unique_ptr<LPVOID, VirtualFreeDeleter> lpbBuffer(VirtualAlloc(nullptr, dwSizeOfFileInfoVer, MEM_COMMIT, PAGE_READWRITE));
	if (lpbBuffer.get() == nullptr)
		return false;

	if (GetFileVersionInfoA(lpszFileName.c_str(), 0, dwSizeOfFileInfoVer, lpbBuffer.get()) == FALSE)
		return false;

	VS_FIXEDFILEINFO *ffi = nullptr;
	if (VerQueryValueA(lpbBuffer.get(), "\\", reinterpret_cast<LPVOID *>(&ffi), (PUINT)&dwSizeOfFileInfoVer) == FALSE)
		return false;

	*lpdwVersion =
		((HIWORD(ffi->dwProductVersionMS) & 0xFF) << 24) |
		((LOWORD(ffi->dwProductVersionMS) & 0xFF) << 16) |
		((HIWORD(ffi->dwProductVersionLS) & 0xFF) << 8) |
		(LOWORD(ffi->dwProductVersionLS) & 0xFF);

	return true;
}


/*******************************************************************************************************************
********************************************************************************************************************
********************************************************************************************************************
*******************************************************************************************************************/


class CloseHandleDeleter
{
public:
	using pointer = HANDLE;

	void operator()(HANDLE handle) const
	{
		CloseHandle(handle);
	}
};

class UnmapViewOfFileDeleter
{
public:
	using pointer = LPVOID;

	void operator()(LPVOID lpBaseAddress) const
	{
		UnmapViewOfFile(lpBaseAddress);
	}
};


constexpr int getNum(char ch)
{
	return (ch == 'S') ? 3 : (ch - 'A');
}

constexpr int isNum(char ch)
{
	return (ch >= '0') && (ch <= '9');
}


bool GetChecksum(const std::string& lpszFormulaString, const std::array<std::string, 3> files, DWORD *lpdwChecksum)
{
	if (files.size() != 3)
		return false;

	char checkrevisionPath[MAX_PATH] = {};
	HMODULE hm = nullptr;
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCSTR)&GetChecksum,
		&hm))
		return false;

	if (GetModuleFileNameA(hm, checkrevisionPath, sizeof(checkrevisionPath)) == 0)
		return false;

	int mpqNumber = std::stoi(std::string(std::strrchr(checkrevisionPath, '.') - 1, 1));
	if (mpqNumber > 7)
		return false;

	std::uint32_t values[4], ovd[4], ovs1[4], ovs2[4];
	char ops[4];
	int curFormula = 0, variable;

	const char *token = lpszFormulaString.c_str();
	while (token && *token)
	{
		if (*(token + 1) == '=')
		{
			variable = getNum(*token);
			if (variable < 0 || variable > 3)
				return false;
			token += 2;
			if (isNum(*token))
			{
				values[variable] = std::strtoul(token, nullptr, 10);
			}
			else
			{
				if (curFormula > 3)
					return false;
				ovd[curFormula] = variable;
				ovs1[curFormula] = getNum(*token);
				ops[curFormula] = *(token + 1);
				ovs2[curFormula] = getNum(*(token + 2));
				curFormula++;
			}
		}

		for (; *token != 0; token++)
		{
			if (*token == ' ')
			{
				token++;
				break;
			}
		}
	}

	values[0] ^= checksumseeds[mpqNumber];

	for (const auto& file : files)
	{
		std::unique_ptr<HANDLE, CloseHandleDeleter> hFile(CreateFileA(file.c_str(), GENERIC_READ, FILE_SHARE_READ,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
		if (hFile.get() == INVALID_HANDLE_VALUE)
			return false;

		LARGE_INTEGER file_len = {};
		if (GetFileSizeEx(hFile.get(), &file_len) == FALSE)
			return false;

		std::unique_ptr<HANDLE, CloseHandleDeleter> hFileMapping(CreateFileMappingA(hFile.get(), nullptr, PAGE_READONLY, 0, 0, nullptr));
		if (!hFileMapping)
			return false;

		std::unique_ptr<LPVOID, UnmapViewOfFileDeleter> file_buffer(MapViewOfFile(hFileMapping.get(), FILE_MAP_READ, 0, 0, 0));
		if (file_buffer == nullptr)
			return false;

		std::uint32_t *current = nullptr;
		void *buff = nullptr;
		std::size_t buffer_size = file_len.QuadPart;
		std::size_t remainder = file_len.QuadPart & 0x3FF;
		if (remainder == 0)
		{
			current = static_cast<std::uint32_t *>(file_buffer.get());
		}
		else
		{
			std::uint8_t pad = 0xFF;

			buffer_size += 1024 - remainder;
			buff = std::malloc(buffer_size);
			std::memcpy(buff, file_buffer.get(), file_len.QuadPart);

			std::uint8_t *pad_dest = static_cast<std::uint8_t *>(buff) + file_len.QuadPart;
			for (auto u = file_len.QuadPart; u < buffer_size; u++)
				*pad_dest++ = pad--;

			current = static_cast<std::uint32_t *>(buff);
		}

		for (std::size_t j = 0; j < (buffer_size / sizeof(std::uint32_t)); j++)
		{
			values[3] = current[j];
			for (int k = 0; k < curFormula; k++)
			{
				switch (ops[k])
				{
				case '+':
					values[ovd[k]] = values[ovs1[k]] + values[ovs2[k]];
					break;
				case '-':
					values[ovd[k]] = values[ovs1[k]] - values[ovs2[k]];
					break;
				case '^':
					values[ovd[k]] = values[ovs1[k]] ^ values[ovs2[k]];
					break;
				default:
					if (buff)
						std::free(buff);
					return false;
				}
			}
		}

		if (buff)
			std::free(buff);
	}

	*lpdwChecksum = values[2];

	return true;
}