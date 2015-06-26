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
#define VERIX86VERSION 1 	//CheckRevision version(ver-ix86-1.dll = 1, ver-ix86-2.dll = 2, etc..)

#include <Windows.h>

const DWORD dwMpqChecksumKeys[8] = {
	0xE7F4CB62lu,
	0xF6A14FFClu,
	0xAA5504AFlu,
	0x871FCDC2lu,
	0x11BF6A18lu,
	0xC57292E6lu,
	0x7927D27Elu,
	0x2FEC8733lu
};

bool GetExeInfo(LPCSTR lpszFileName, char *lpExeInfoString);
bool GetExeVer(LPCSTR lpszFileName, unsigned long * lpdwVersion);
bool GetChecksum(LPCSTR lpszFileName1, LPCSTR lpszFileName2, LPCSTR lpszFileName3, int lpszValueString, unsigned long * lpdwChecksum);