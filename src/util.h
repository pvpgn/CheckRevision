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


#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#include <Windows.h>


const std::array<std::uint32_t, 8> checksumseeds = {
	0xE7F4CB62,
	0xF6A14FFC,
	0xAA5504AF,
	0x871FCDC2,
	0x11BF6A18,
	0xC57292E6,
	0x7927D27E,
	0x2FEC8733
};

bool GetExeInfo(const std::string& lpszFileName, char *lpszExeInfoString);
bool GetExeVer(const std::string& lpszFileName, DWORD *lpdwVersion);
bool GetChecksum(const std::string& lpszFormulaString, const std::array<std::string, 3> files, DWORD *lpdwChecksum);