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

FILE* hLog = 0;
unsigned int dirCount = 0, captures=0, events=0;
const DWORD dwNotificationFlags = FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_FILE_NAME;

namespace fs = std::filesystem;

//typedef int (*real_printf)(const char*, ...);
//#define real_printf printf
//#define	printf my_printf 

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

void readOpts(int argc, TCHAR* argv[])
{

	if (argc > 1) {
		if (argv[1][0] == '/') argv[1][0] = '-';
		if (_tcscmp(argv[1], _T("-h")) == 0 || _tcscmp(argv[1], _T("-?")) == 0 || _tcscmp(argv[1], _T("-help")) == 0) {
			system("cls");
			printf("\ndirwatch_cli: \n");
			printf("\t -save <dir>   save changed files to dir. Can create, parent path must exist\n");
			printf("\t -watch <dir>  a directory to watch, always recursive, must exist, default c:\\\n");
			printf("\t -h -? -help  this help screen. Note switches support / or - prefix.\n");
			printf("\t Auto saves log<date>.txt to save dir if specified.");
			printf("\t Based on ReadDirectoryChangesW sample from James E Beveridge Copyright (c) 2010\n\n");
			exit(0);
		}
	}

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '/') argv[i][0] = '-';

		if (_tcscmp(argv[i], _T("-save")) ==0) {
			if ((i + 1) >= argc) {
				printf("-save missing path argument\n");
				exit(0);
			}
			saveDir = argv[i+1];
			if (!fs::is_directory((LPCWSTR)saveDir)) {
				if (!fs::create_directory((LPCWSTR)saveDir)) {
					printf("Could not create -save dirtectory: %ls\n", (LPCWSTR)saveDir);
					exit(0);
				}
			}
			printf("Save directory: %ls\n", (LPCWSTR)saveDir);

			logFile = "";
			time_t now = time(NULL);
			struct tm* tms = localtime(&now);
			logFile.AppendFormat(L"%s\\log_%d.%d.%d_%d.%d.%d.txt", (LPCWSTR)saveDir, tms->tm_mday, tms->tm_mon, tms->tm_year, tms->tm_hour, tms->tm_min, tms->tm_sec);
			if (hLog != 0) fclose(hLog);
			CT2A ascii(logFile);
			hLog = fopen(ascii.m_psz, "w");
			if (hLog != NULL) printf("Logfile: %ls\n", (LPCWSTR)logFile);

		}

		if (_tcscmp(argv[i], _T("-watch")) == 0) {
			if ((i + 1) >= argc) {
				printf("-watch missing path argument\n");
				exit(0);
			}
			if (!fs::is_directory(argv[i + 1])){
					printf("-watch dirtectory not found: %ls\n", argv[i + 1]);
					exit(0);
			}
			else {
				//todo: read a -r for recursive, for now always recursive...
				dirCount++;
				changes.AddDirectory(argv[i + 1], true, dwNotificationFlags);
				printf("Watching %ls\n", argv[i + 1]);
				
			}
		}

	}


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

	char buf[MAX_PATH];
	bool bTerminate = false;


	while (!bTerminate)
	{
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
					if (saveDir.GetLength() > 0) {
						if(wstrFilename.Left(saveDir.GetLength()) == saveDir){
							mprintf(L"ignoring %ls\n", (LPCWSTR)wstrFilename);
							 //its us...ignore do not notify..
						}
						else {
							events++;
							mprintf(L"%ls %ls\n", ExplainAction(dwAction), (LPCWSTR)wstrFilename);
							if (dwAction == FILE_ACTION_ADDED || dwAction == FILE_ACTION_MODIFIED) {
								SafeSaveFile(wstrFilename);
							}
						}
					}
					else {
						events++;
						mprintf(L"%ls %ls\n", ExplainAction(dwAction), (LPCWSTR)wstrFilename);
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
	case FILE_ACTION_ADDED            :
		return L"Added";
	case FILE_ACTION_REMOVED          :
		return L"Deleted";
	case FILE_ACTION_MODIFIED         :
		return L"Modified";
	case FILE_ACTION_RENAMED_OLD_NAME :
		return L"Renamed From";
	case FILE_ACTION_RENAMED_NEW_NAME :
		return L"Renamed To";
	default:
		return L"BAD DATA";
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
