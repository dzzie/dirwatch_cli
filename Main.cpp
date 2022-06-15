//
//	The MIT License
//
//	Copyright (c) 2010 James E Beveridge
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in
//	all copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//	THE SOFTWARE.


//	This sample code is for my blog entry titled, "Understanding ReadDirectoryChangesW"
//	http://qualapps.blogspot.com/2010/05/understanding-readdirectorychangesw.html
//	See ReadMe.txt for overview information.


#include "stdafx.h"
#include "ReadDirectoryChanges.h"
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>
#include <filesystem>
#include <string_view>
#include <time.h>
#include <vector>
#include <string>
#include "atlbase.h"
#include "atlstr.h"
#include "comutil.h"
 
LPCWSTR ExplainAction( DWORD dwAction );
bool TryGetKeyboardInput( HANDLE hStdIn, bool &bTerminate, char* buf );


//
// When the application starts, it immediately starts monitoring your home
// directory, including children, as well as C:\, not including children.
// The application exits when you hit Esc.
// You can add a directory to the monitoring list by typing the directory
// name and hitting Enter. Notifications will pause while you type.
//

CStringW saveDir;
CStringW logFile;
CReadDirectoryChanges changes;
vector<CStringW> exclude;
vector<CStringW> exclude_pattern;

FILE* hLog = 0;
bool showIgnored = false;
bool bTerminate = false;
unsigned int dirCount = 0, captures=0, events=0;
const DWORD dwNotificationFlags = FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_FILE_NAME;

namespace fs = std::filesystem;

int mprintf(wchar_t* format, ...) {

	wchar_t* ret = 0;
	wchar_t buf[1024]; //avoid malloc/free for short strings if we can
	bool alloced = false;

	if (!format) return 0;

	va_list args;
	va_start(args, format);
	int size = _vscwprintf(format, args);
	if (size == 0) { va_end(args); return 0; }

	if (size < 1020) {
		ret = &buf[0];
	}
	else {
		alloced = true;
		size++; //for null
		ret = (wchar_t*)malloc(size + 2);
		if (ret == 0) { va_end(args); return 0; }
	}

	_vsnwprintf(ret, size, format, args);
	ret[size] = 0; //explicitly null terminate
	va_end(args);

	//here is where you could forward the char* to a UI handler..
	//MessageBoxA(0, ret, "Hooked printf!", 0);

	printf("%ls", ret);
	if (hLog != NULL) {
		fwprintf(hLog, L"%s", ret);
		fflush(hLog);
	}

	if (alloced) free(ret);
	return 0;
}

int file_length(FILE* f)
{
	int pos;
	int end;

	pos = ftell(f);
	fseek(f, 0, SEEK_END);
	end = ftell(f);
	fseek(f, pos, SEEK_SET);

	return end;
}

vector<string> split(string data, string delim, bool caseInsensitive = true) {
	size_t pos_start = 0, pos_end, delim_len = delim.length();
	string token;
	vector<string> res;

	string s = data;
	string delimiter = delim;

	if (caseInsensitive) {
		std::transform(s.begin(), s.end(), s.begin(), tolower);
		std::transform(delimiter.begin(), delimiter.end(), delimiter.begin(), tolower);
	}

	while ((pos_end = s.find(delimiter, pos_start)) != string::npos) {
		token = data.substr(pos_start, pos_end - pos_start);
		pos_start = pos_end + delim_len;
		res.push_back(token);
	}

	res.push_back(data.substr(pos_start));
	return res;
}

const char* stripChars = " \t\n\r\f\v\"'";

// trim from end of string (right)
inline std::string& rtrim(std::string& s, const char* t = stripChars)
{
	s.erase(s.find_last_not_of(t) + 1);
	return s;
}

// trim from beginning of string (left)
inline std::string& ltrim(std::string& s, const char* t = stripChars)
{
	s.erase(0, s.find_first_not_of(t));
	return s;
}

// trim from both ends of string (right then left)
inline std::string& trim(std::string& s, const char* t = stripChars)
{
	return ltrim(rtrim(s, t), t);
}

CStringW expandEnv(TCHAR* arg) {
	CStringW tmp;
	TCHAR buf[2000]; //should never be longer than this I dont want to malloc..
	DWORD sz = ExpandEnvironmentStringsW(arg, buf, 2000);

	if (sz == 0 || sz >= 2000) {
		tmp = arg;
		return tmp;
	}

	tmp = buf;
	return tmp;
}

void parseExcludeFile(CStringW path) {

	FILE* fp;
	CT2A ascii(path);
	fp = fopen(ascii.m_psz, "rb");

	if (fp == 0) {
		printf("Failed to open exclude file %ls\n", (LPCWSTR)path);
		exit(0);
	}

	int size = file_length(fp);
	char* buf = (char*)malloc(size + 10);
	
	if (buf == NULL) {
		printf("malloc failed for %d bytes\n", size);
		exit(0);
	}

	memset(buf, 0x00, size + 10);
	fread(buf, 1, size, fp);
	fclose(fp);

	string ex = buf;
	vector<string> vs = split(ex, "\n");
	free(buf);

	for (std::vector<string>::iterator si = vs.begin(); si != vs.end(); ++si) {
		string s = *si;
		s = trim(s);
		if (s.length() > 0) {
			//CStringW cs(s.c_str(), s.length());
			CStringW cs = expandEnv((TCHAR*)s.c_str());
			if (cs.FindOneOf(L"*?[") >= 0) {
				exclude_pattern.push_back(cs);
				printf("Exclusion Pattern added: %ls\n", (LPCWSTR)cs);
			}
			else {
				exclude.push_back(cs);
				printf("Exclusion added: %ls\n", (LPCWSTR)cs);
			}
		}
	}

	if (exclude_pattern.empty() && exclude.empty()) {
		printf("Nothing added from exclude file?\n");
		exit(0);
	}
}

void readOpts(int argc, TCHAR* argv[])
{

	CStringW cs;

	if (argc > 1) {
		if (argv[1][0] == '/') argv[1][0] = '-';
		if (_tcscmp(argv[1], _T("-h")) == 0 || _tcscmp(argv[1], _T("-?")) == 0 || _tcscmp(argv[1], _T("-help")) == 0) {
			system("cls");
			printf("\ndirwatch_cli: \n");
			printf("\t -save <dir>         save changed files to dir. Can create, parent path must exist\n");
			printf("\t -watch <dir>        a directory to watch, always recursive, must exist, default c:\\\n");
			printf("\t -ex <path/pattern>  exclude a path/fragment or pattern (from sqllite supports: *?[])\n");
			printf("\t -exf <path>         added excludes from <file path>\n");
			printf("\t -si                 show ignored paths in output\n");
			printf("\t -log                manually specify log file (does not require -save)\n");
			printf("\t -h -? -help         this help screen. Note switches support / or - prefix.\n\n");
			printf("\t Auto saves log<date>.txt to -save dir if set and no -log override.\n");
			printf("\t All args expand env vars (%cd% is current dir)\n");
			printf("\t Based on sample by James E Beveridge (c) 2010\n\n");
			exit(0);
		}
	}

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '/') argv[i][0] = '-';

		if (_tcscmp(argv[i], _T("-si")) == 0) showIgnored = true;

		if (_tcscmp(argv[i], _T("-log")) == 0) {
			if ((i + 1) >= argc) {
				printf("-ex missing argument\n");
				exit(0);
			}
			else {
				if (hLog != 0) fclose(hLog);
				if (!logFile.IsEmpty() && PathFileExists((LPCWSTR)logFile)) remove((const char*)(LPCWSTR)logFile);
				logFile = expandEnv(argv[i + 1]);
				CT2A ascii(logFile);
				hLog = fopen(ascii.m_psz, "w");
				if (hLog != NULL) {
					printf("Logfile: %ls\n", (LPCWSTR)logFile);
				}
				else {
					printf("Failed to open logfile: %ls\n", (LPCWSTR)logFile);
					exit(0);
				}
			}
		}

		if (_tcscmp(argv[i], _T("-save")) ==0) {
			
			if (!saveDir.IsEmpty()) {
				printf("SaveDir can only be specified once\n");
				exit(0);
			}

			if ((i + 1) >= argc) {
				printf("-save missing path argument\n");
				exit(0);
			}

			saveDir = expandEnv(argv[i+1]);
			if (!fs::is_directory((LPCWSTR)saveDir)) {
				if (!fs::create_directory((LPCWSTR)saveDir)) {
					printf("Could not create -save dirtectory: %ls\n", (LPCWSTR)saveDir);
					exit(0);
				}
			}
			printf("Save directory: %ls\n", (LPCWSTR)saveDir);

			if(logFile.IsEmpty()) {
				time_t now = time(NULL);
				struct tm* tms = localtime(&now);
				logFile.AppendFormat(L"%s\\log_%d.%d.%d_%d.%d.%d.txt", (LPCWSTR)saveDir, tms->tm_mday, tms->tm_mon, tms->tm_year, tms->tm_hour, tms->tm_min, tms->tm_sec);
				if (hLog != 0) fclose(hLog);
				CT2A ascii(logFile);
				hLog = fopen(ascii.m_psz, "w");
				if (hLog != NULL){
					printf("Logfile: %ls\n", (LPCWSTR)logFile);
				}
				else {
					printf("Failed to open logfile: %ls\n", (LPCWSTR)logFile);
					exit(0);
				}
			}

		}

		if (_tcscmp(argv[i], _T("-watch")) == 0) {
			if ((i + 1) >= argc) {
				printf("-watch missing path argument\n");
				exit(0);
			}
			CStringW wd = expandEnv(argv[i + 1]);
			if (!fs::is_directory((LPCWSTR)wd)){
					printf("-watch dirtectory not found: %ls\n", (LPCWSTR)wd);
					exit(0);
			}
			else {
				//todo: read a -r for recursive, for now always recursive...
				dirCount++;
				changes.AddDirectory((LPCWSTR)wd, true, dwNotificationFlags);
				printf("Watching %ls\n", (LPCWSTR)wd);
				
			}
		}

		if (_tcscmp(argv[i], _T("-ex")) == 0) {
			if ((i + 1) >= argc) {
				printf("-ex missing argument\n");
				exit(0);
			}
			else {
				cs = expandEnv(argv[i + 1]);
				if (cs.FindOneOf(L"*?[") >= 0) {
					exclude_pattern.push_back(cs);
					printf("Exclusion Pattern added: %ls\n", (LPCWSTR)cs);
				}
				else {
					exclude.push_back(cs);
					printf("Exclusion added: %ls\n", (LPCWSTR)cs);
				}

			}
		}

		if (_tcscmp(argv[i], _T("-exf")) == 0) {
			if ((i + 1) >= argc) {
				printf("-exf missing path argument\n");
				exit(0);
			}
			else {
				cs = expandEnv(argv[i + 1]);
				parseExcludeFile(cs);
			}
		}

	}

}

//---------------------LIKE (ripped from sqllite)------------------------------
//https://stackoverflow.com/questions/22099599/sql-like-similar-use-in-c
//I did a half ass conversion to accept wchar seems to work ok on ansi wchar anyway..
/*
** This lookup table is used to help decode the first byte of
** a multi-byte UTF8 character.
*/
static const unsigned char sqlite3Utf8Trans1[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x00,
};

typedef  unsigned int u32;
typedef  wchar_t u8;

u32 sqlite3Utf8Read(
	wchar_t** pz    /* Pointer to string from which to read char */
) {
	unsigned int c;

	/* Same as READ_UTF8() above but without the zTerm parameter.
	** For this routine, we assume the UTF8 string is always zero-terminated.
	*/
	c = *((*pz)++);
	if (c >= 0xc0) {
		c = sqlite3Utf8Trans1[c - 0xc0];
		while ((*(*pz) & 0xc0) == 0x80) {
			c = (c << 6) + (0x3f & *((*pz)++));
		}
		if (c < 0x80
			|| (c & 0xFFFFF800) == 0xD800
			|| (c & 0xFFFFFFFE) == 0xFFFE) {
			c = 0xFFFD;
		}
	}
	return c;
}

/*
** Assuming zIn points to the first byte of a UTF-8 character,
** advance zIn to point to the first byte of the next UTF-8 character.
*/
#define SQLITE_SKIP_UTF8(zIn) {                        \
  if( (*(zIn++))>=0xc0 ){                              \
      while( (*zIn & 0xc0)==0x80 ){ zIn++; }             \
    }                                                    \
}

const unsigned char sqlite3UpperToLower[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
	18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
	36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
	54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 97, 98, 99, 100, 101, 102, 103,
	104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
	122, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
	108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
	126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
	144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161,
	162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
	180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197,
	198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
	216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
	234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
	252, 253, 254, 255
};

# define GlobUpperToLower(A)   if( !((A)&~0x7f) ){ A = sqlite3UpperToLower[A]; }

/*
** Compare two UTF-8 strings for equality where the first string can
** potentially be a "glob" expression.  Return true (1) if they
** are the same and false (0) if they are different.
**
** Globbing rules:
**
**      '*'       Matches any sequence of zero or more characters.
**
**      '?'       Matches exactly one character.
**
**     [...]      Matches one character from the enclosed list of
**                characters.
**
**     [^...]     Matches one character not in the enclosed list.
**
** With the [...] and [^...] matching, a ']' character can be included
** in the list by making it the first character after '[' or '^'.  A
** range of characters can be specified using '-'.  Example:
** "[a-z]" matches any single lower-case letter.  To match a '-', make
** it the last character in the list.
**
** This routine is usually quick, but can be N**2 in the worst case.
**
** Hints: to match '*' or '?', put them in "[]".  Like this:
**
**         abc[*]xyz        Matches "abc*xyz" only
*/
static int patternCompare(
	u8* zPattern,              /* The glob pattern */
	u8* zString
)

{
	u32 c, c2;
	int invert;
	int seen;
	const u8 matchOne = '?';
	const u8 matchAll = '*';
	const u8 matchSet = '[';
	const u8 noCase = 0;
	int prevEscape = 0;     /* True if the previous character was 'escape' */
	u32 esc = 0;

	//u32 esc;                         /* The escape character */

	while ((c = sqlite3Utf8Read(&zPattern)) != 0) {
		if (c == matchAll && !prevEscape) {
			while ((c = sqlite3Utf8Read(&zPattern)) == matchAll
				|| c == matchOne) {
				if (c == matchOne && sqlite3Utf8Read(&zString) == 0) {
					return 0;
				}
			}
			if (c == 0) {
				return 1;
			}
			else if (c == esc) {
				c = sqlite3Utf8Read(&zPattern);
				if (c == 0) {
					return 0;
				}
			}
			else if (c == matchSet) {
				//assert(esc == 0);         /* This is GLOB, not LIKE */
				//assert(matchSet<0x80);  /* '[' is a single-byte character */
				while (*zString && patternCompare(&zPattern[-1], zString) == 0) {
					SQLITE_SKIP_UTF8(zString);
				}
				return *zString != 0;
			}
			while ((c2 = sqlite3Utf8Read(&zString)) != 0) {
				if (noCase) {
					GlobUpperToLower(c2);
					GlobUpperToLower(c);
					while (c2 != 0 && c2 != c) {
						c2 = sqlite3Utf8Read(&zString);
						GlobUpperToLower(c2);
					}
				}
				else {
					while (c2 != 0 && c2 != c) {
						c2 = sqlite3Utf8Read(&zString);
					}
				}
				if (c2 == 0) return 0;
				if (patternCompare(zPattern, zString)) return 1;
			}
			return 0;
		}
		else if (c == matchOne && !prevEscape) {
			if (sqlite3Utf8Read(&zString) == 0) {
				return 0;
			}
		}
		else if (c == matchSet) {
			u32 prior_c = 0;
			//assert(esc == 0);    /* This only occurs for GLOB, not LIKE */
			seen = 0;
			invert = 0;
			c = sqlite3Utf8Read(&zString);
			if (c == 0) return 0;
			c2 = sqlite3Utf8Read(&zPattern);
			if (c2 == '^') {
				invert = 1;
				c2 = sqlite3Utf8Read(&zPattern);
			}
			if (c2 == ']') {
				if (c == ']') seen = 1;
				c2 = sqlite3Utf8Read(&zPattern);
			}
			while (c2 && c2 != ']') {
				if (c2 == '-' && zPattern[0] != ']' && zPattern[0] != 0 && prior_c > 0) {
					c2 = sqlite3Utf8Read(&zPattern);
					if (c >= prior_c && c <= c2) seen = 1;
					prior_c = 0;
				}
				else {
					if (c == c2) {
						seen = 1;
					}
					prior_c = c2;
				}
				c2 = sqlite3Utf8Read(&zPattern);
			}
			if (c2 == 0 || (seen ^ invert) == 0) {
				return 0;
			}
		}
		else if (esc == c && !prevEscape) {
			prevEscape = 1;
		}
		else {
			c2 = sqlite3Utf8Read(&zString);
			if (noCase) {
				GlobUpperToLower(c);
				GlobUpperToLower(c2);
			}
			if (c != c2) {
				return 0;
			}
			prevEscape = 0;
		}
	}
	return *zString == 0;
}




CStringW HashFile(LPCWSTR path) {

		#define BUFSIZE 1024
		#define MD5LEN  16

		DWORD dwStatus = 0;
		BOOL bResult = FALSE;
		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0;
		HANDLE hFile = NULL;
		BYTE rgbFile[BUFSIZE];
		DWORD cbRead = 0;
		BYTE rgbHash[MD5LEN];
		DWORD cbHash = 0;
		CHAR rgbDigits[] = "0123456789abcdef";
		
		CStringW ret;

		hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL);

		if (INVALID_HANDLE_VALUE == hFile)
		{
			dwStatus = GetLastError();
			//printf("Error opening file %ls\nError: %d\n", path, dwStatus);
			goto exitnow;
		}

		// Get handle to the crypto provider
		if (!CryptAcquireContext(&hProv,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))
		{
			dwStatus = GetLastError();
			//printf("CryptAcquireContext failed: %d\n", dwStatus);
			CloseHandle(hFile);
			goto exitnow;
		}

		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			dwStatus = GetLastError();
			//printf("CryptAcquireContext failed: %d\n", dwStatus);
			CloseHandle(hFile);
			CryptReleaseContext(hProv, 0);
			goto exitnow;
		}

		while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
			&cbRead, NULL))
		{
			if (0 == cbRead) break;

			if (!CryptHashData(hHash, rgbFile, cbRead, 0))
			{
				dwStatus = GetLastError();
				//printf("CryptHashData failed: %d\n", dwStatus);
				CryptReleaseContext(hProv, 0);
				CryptDestroyHash(hHash);
				CloseHandle(hFile);
				goto exitnow;
			}
		}

		if (!bResult)
		{
			dwStatus = GetLastError();
			//printf("ReadFile failed: %d\n", dwStatus);
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			goto exitnow;
		}

		cbHash = MD5LEN;
		if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
		{
			//printf("MD5 hash of file %ls is: ", path);
			for (DWORD i = 0; i < cbHash; i++)
			{
				ret.AppendFormat(L"%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
			}
		}
		else
		{
			dwStatus = GetLastError();
			//printf("CryptGetHashParam failed: %d\n", dwStatus);
		}

		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		CloseHandle(hFile);

exitnow:
		return ret;
}

bool SafeSaveFile(CStringW existing) {
	
	if (saveDir.GetLength() == 0) return false;

	CStringW buf;

	fs::path p = (LPCWSTR)existing;
	fs::path base = p.stem();
	fs::path ext = p.extension();

	int i = 0;
	//CStringW hash = HashFile((LPCWSTR)existing);
	//printf("\t md5(%ls) = %ls\n", (LPCWSTR)existing, (LPCWSTR)hash);

	/*while (1) {
		i++;
		buf = saveDir;
		buf.AppendFormat(L"\\%s_%x_%d%s", base.c_str(), GetTickCount(), i, ext.c_str());
		if (!fs::exists((LPCWSTR)buf)) break;
		if (i > 1000) break;
	}*/

	buf = saveDir;
	buf.AppendFormat(L"\\%s_%x_%s", base.c_str(), GetTickCount(), ext.c_str());
	if (fs::exists((LPCWSTR)buf)) return false; //1 copy = added + 3 modified events..time stamp should be enough for unique..

	if (CopyFile((LPCWSTR)existing, (LPCWSTR)buf, true) == 0 ) {
		mprintf(L"\t Failed to capture: %ls -> %ls\n", (LPCWSTR)existing, (LPCWSTR)buf);
	}
	else {
		mprintf(L"\t Saved as: %ls\n", (LPCWSTR)buf);
		captures++;
	}


}


int __stdcall ctrl_c_handler(DWORD arg) {
	if (arg == 0) { //ctrl_c event
		bTerminate = true;
		return TRUE;
	}
	return FALSE;
}


int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	
	mprintf(L"\n");
	readOpts(argc, argv); //exit if failed parse cmdline
	mprintf(L"Watch Count = %d\n", dirCount);

	if(dirCount < 1){
		mprintf(L"No monitor directories specified, defaulting to C:\\\n");
		changes.AddDirectory(_T("C:\\"), true, dwNotificationFlags);
	}
	
	if (saveDir.GetLength() == 0) mprintf(L"No -save <dir> specified. feature unavailable...\n");
	
	HANDLE hStdIn =  ::GetStdHandle(STD_INPUT_HANDLE);
	const HANDLE handles[] = { hStdIn, changes.GetWaitHandle() };

	int p = 0;
	char buf[MAX_PATH];
	bool ignoreIt = false;
	std::vector<CStringW>::iterator csi;

	setvbuf(stdout, NULL, _IONBF, 0); //autoflush - allows external apps to read cmdline output in realtime..
	SetConsoleCtrlHandler(ctrl_c_handler, TRUE); //http://msdn.microsoft.com/en-us/library/ms686016

	while (!bTerminate)
	{
		ignoreIt = false;
		DWORD rc = ::WaitForMultipleObjectsEx(_countof(handles), handles, false, INFINITE, true);

		switch (rc)
		{
		case WAIT_OBJECT_0 + 0:
			// hStdIn was signaled. This can happen due to mouse input, focus change, Shift keys, and more.  Delegate to TryGetKeyboardInput().
			// TryGetKeyboardInput sets bTerminate to true if the user hits Esc.
			if (TryGetKeyboardInput(hStdIn, bTerminate, buf))
				changes.AddDirectory(CStringW(buf), false, dwNotificationFlags);
			break;

		case WAIT_OBJECT_0 + 1:
			// We've received a notification in the queue.
			{
				DWORD dwAction;
				CStringW wstrFilename;
				if (changes.CheckOverflow())
					mprintf(L"Queue overflowed.\n");
				else
				{
					changes.Pop(dwAction, wstrFilename);

					if (logFile.GetLength() > 0 && wstrFilename == logFile) {
						ignoreIt = true;
						if (showIgnored) mprintf(L"** IGNORED: LogFile %ls %ls\n", ExplainAction(dwAction), (LPCWSTR)wstrFilename);
					}

					if (!ignoreIt && saveDir.GetLength() > 0 && wstrFilename.Left(saveDir.GetLength()) == saveDir) { //safe if getlength > path.length
						ignoreIt = true;
						if (showIgnored) mprintf(L"** IGNORED: SaveDir %ls %ls\n", ExplainAction(dwAction), (LPCWSTR)wstrFilename);
					}

					if (!ignoreIt && !exclude.empty()) {
						for (csi = exclude.begin(); csi != exclude.end(); ++csi) {
							if (wstrFilename.Find(*csi) >= 0) {
								ignoreIt = true;
								if (showIgnored) mprintf(L"** IGNORED: Exclude '%ls' %ls %ls\n", (LPCWSTR)*csi, ExplainAction(dwAction), (LPCWSTR)wstrFilename);
								break; //for
							}
						}
					}

					if (!ignoreIt && !exclude_pattern.empty()) {
						for (csi = exclude_pattern.begin(); csi != exclude_pattern.end(); ++csi) {
							if (patternCompare((u8*)(LPCWSTR)*csi, (u8*)(LPCWSTR)wstrFilename) != 0){
								ignoreIt = true;
								if (showIgnored) mprintf(L"** IGNORED: Exclude Pattern '%ls' %ls  %ls\n", (LPCWSTR)*csi, ExplainAction(dwAction), (LPCWSTR)wstrFilename);
								break; //for
							}
						}
					}

					if (!ignoreIt) {
						events++;
						mprintf(L"%ls %ls\n", ExplainAction(dwAction), (LPCWSTR)wstrFilename);
						if (saveDir.GetLength() > 0 && (dwAction == FILE_ACTION_ADDED || dwAction == FILE_ACTION_MODIFIED)) {
							SafeSaveFile(wstrFilename);
						}
					}
				}
			}
			break;

		case WAIT_IO_COMPLETION:
			// Nothing to do.
			break;

		}
	}

	// Just for sample purposes. The destructor will call Terminate() automatically.
	changes.Terminate();

	mprintf(L"Complete %d events and %d captures made.\n", events, captures);
	return EXIT_SUCCESS;
}

LPCWSTR ExplainAction( DWORD dwAction )
{
	switch (dwAction)
	{
		case FILE_ACTION_ADDED:				return L"Added";
		case FILE_ACTION_REMOVED:			return L"Deleted";
		case FILE_ACTION_MODIFIED:			return L"Modified";
		case FILE_ACTION_RENAMED_OLD_NAME:  return L"Renamed From";
		case FILE_ACTION_RENAMED_NEW_NAME:  return L"Renamed To";
		default:                            return L"BAD DATA";
	}
}

bool TryGetKeyboardInput( HANDLE hStdIn, bool &bTerminate, char* buf )
{
	DWORD dwNumberOfEventsRead=0;
	INPUT_RECORD rec = {0};

	if (!::PeekConsoleInput(hStdIn, &rec, 1, &dwNumberOfEventsRead))
		return false;

	if (rec.EventType == KEY_EVENT)
	{
		if (rec.Event.KeyEvent.wVirtualKeyCode == VK_ESCAPE)
			bTerminate = true;
		/*else if (rec.Event.KeyEvent.wVirtualKeyCode > VK_HELP)
		{
			if (!gets(buf))	// End of file, usually Ctrl-Z
				bTerminate = true;
			else
				return true;
		}*/
	}

	::FlushConsoleInputBuffer(hStdIn);

	return false;
}
