/*

	NoMoreCrashing Loader v1.0
	Authored by Nassic (https://github.com/nasiratif/NoMoreCrashing)

*/

#include <Windows.h>
#include <windowsx.h>
#include <strsafe.h>
#include <Shlwapi.h>
#include <shlobj_core.h>
#include <shellapi.h>
#include <Psapi.h>
#include "resource.h"

#define BEA_ENGINE_STATIC
#include <beaengine/BeaEngine.h>
#include <map>
#include <vector>

// DEFINES:
// -----
#define PID_LAUNCH_EXTERNAL DWORD(-1)
// -----

// Enable visual styles
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#ifdef _WIN64
#define INJECTOR_DLL TEXT("injector-x64.dll")
#else
#define INJECTOR_DLL TEXT("injector-x86.dll")
#endif

HINSTANCE hInst;

struct ThreadContext
{
	HANDLE hDebugThread;
	DWORD hDebugThreadID;

	HANDLE hDebugError;
	HANDLE hDebugLoadDone;

	DWORD pidToDebug;
	TCHAR ret[1024];
};

// SETTINGS:
// -----
bool debugInjection = false;
bool sawDebugWarning = false;

TCHAR appFileName[MAX_PATH] = TEXT("");
TCHAR appWorkingDir[MAX_PATH] = TEXT("");
// -----

/*

---------- UTILITY FUNCTIONS ----------

*/

bool ArchMatches(HANDLE hProcess)
{
	BOOL isx86 = FALSE;
#ifdef _WIN64
	IsWow64Process(hProcess, &isx86);
	if (isx86)
		return false;
#else
	BOOL isWOW64 = FALSE;
	IsWow64Process(GetCurrentProcess(), &isWOW64);
	if (isWOW64)
		IsWow64Process(hProcess, &isx86);
	else
		isx86 = TRUE;
	if (!isx86)
		return false;
#endif

	return true;
}

void ReleaseThreadContext(ThreadContext* thread)
{
	CloseHandle(thread->hDebugError);
	CloseHandle(thread->hDebugLoadDone);
	delete thread;
}

DWORD WINAPI DebugThread(LPVOID pThread)
{
	auto self = (ThreadContext*)pThread;

	ResetEvent(self->hDebugError);
	memset(self->ret, 0x0, sizeof(self->ret));

	BOOL success;
	if (self->pidToDebug == PID_LAUNCH_EXTERNAL)
	{
		STARTUPINFO startupInfo = {};
		startupInfo.cb = sizeof(startupInfo);
		PROCESS_INFORMATION processInfo;

		success = CreateProcess(NULL, appFileName, NULL, NULL, FALSE, CREATE_SUSPENDED | DEBUG_PROCESS, NULL, appWorkingDir, &startupInfo, &processInfo);
		if (success)
		{
			success = GetProcessImageFileName(processInfo.hProcess, self->ret, ARRAYSIZE(self->ret));
			if (success)
			{
				success = ArchMatches(processInfo.hProcess);
				if (!success)
				{
					StringCbCopy(self->ret, sizeof(self->ret), TEXT("Incompatible process architecture."));
					TerminateProcess(processInfo.hProcess, 1);
					CloseHandle(processInfo.hProcess);
				}
				ResumeThread(processInfo.hThread);
			}
			else
			{
				StringCbCopy(self->ret, sizeof(self->ret), TEXT("Cannot retrieve process image filename."));
				TerminateProcess(processInfo.hProcess, 1);
				CloseHandle(processInfo.hProcess);
			}
			CloseHandle(processInfo.hThread);
		}
		else
		{
			FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), 0, self->ret, ARRAYSIZE(self->ret), NULL);
		}
	}
	else
	{
		success = DebugActiveProcess(self->pidToDebug);
		if (success)
		{
			auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, self->pidToDebug);
			if (hProcess)
			{
				success = GetProcessImageFileName(hProcess, self->ret, ARRAYSIZE(self->ret));
				if (success)
				{
					success = ArchMatches(hProcess);
					if (!success)
					{
						StringCbCopy(self->ret, sizeof(self->ret), TEXT("Incompatible process architecture."));
						CloseHandle(hProcess);
					}
				}
				else
				{
					StringCbCopy(self->ret, sizeof(self->ret), TEXT("Cannot retrieve process image filename."));
					CloseHandle(hProcess);
				}
			}
			else
			{
				FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), 0, self->ret, ARRAYSIZE(self->ret), NULL);
				success = FALSE;
			}
		}
		else
		{
			FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), 0, self->ret, ARRAYSIZE(self->ret), NULL);
		}
	}

	if (!success)
	{
		SetEvent(self->hDebugError);
		SetEvent(self->hDebugLoadDone);
		return 1;
	}

	SetEvent(self->hDebugLoadDone);
	DebugSetProcessKillOnExit(FALSE);
	while (true)
	{
		DEBUG_EVENT dbgEvent;
		if (WaitForDebugEvent(&dbgEvent, INFINITE))
		{
			switch (dbgEvent.dwDebugEventCode)
			{
			case EXIT_PROCESS_DEBUG_EVENT:
			{
				DebugActiveProcessStop(dbgEvent.dwProcessId);
				ReleaseThreadContext(self);
				return 0;
			}
			case EXCEPTION_DEBUG_EVENT:
			{
				HANDLE hProcess = NULL, hThread = NULL;
				CONTEXT cRecord;
				DISASM disasm = {};

				auto& eRecord = dbgEvent.u.Exception.ExceptionRecord;
				if (eRecord.ExceptionFlags & EXCEPTION_NONCONTINUABLE || eRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
					goto finished;

				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbgEvent.dwProcessId);
				if (!hProcess)
					goto finished;

				hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
				if (!hThread)
					goto finished;

				cRecord.ContextFlags = CONTEXT_CONTROL;
				if (!GetThreadContext(hThread, &cRecord))
					goto finished;

				if (eRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && eRecord.ExceptionInformation[0] == 0x8)
#ifdef _WIN64
				{
					ReadProcessMemory(hProcess, (DWORD64*)cRecord.Rsp, &cRecord.Rip, sizeof(cRecord.Rip), NULL);
					cRecord.Rsp += sizeof(DWORD64);
				}
				else
				{

					BYTE instrs[16];
					UINT bytesRead = 0;

					auto ip = (BYTE*)cRecord.Rip;
					while (ReadProcessMemory(hProcess, ip++, instrs + bytesRead++, 1, NULL))
						if (bytesRead >= sizeof(instrs))
							break;

					disasm.EIP = (UIntPtr)instrs;
					cRecord.Rip += Disasm(&disasm);
				}
#else
				{
					ReadProcessMemory(hProcess, (DWORD*)cRecord.Esp, &cRecord.Eip, sizeof(cRecord.Esp), NULL);
					cRecord.Esp += sizeof(DWORD);
				}
				else
				{
					BYTE instrs[16];
					UINT bytesRead = 0;

					auto ip = (BYTE*)cRecord.Eip;
					while (ReadProcessMemory(hProcess, ip++, instrs + bytesRead++, 1, NULL))
						if (bytesRead >= sizeof(instrs))
							break;

					disasm.EIP = (UIntPtr)instrs;
					cRecord.Eip += Disasm(&disasm);
				}
#endif
				SetThreadContext(hThread, &cRecord);

			finished:
				if (hProcess)
					CloseHandle(hProcess);
				if (hThread)
					CloseHandle(hThread);
				break;
			}
			}
			ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
		}
	}
	return 0;
}

bool AddDebugThread(HWND hDlg, DWORD pid, bool showSuccess = true)
{
	auto thread = new ThreadContext;
	thread->hDebugError = CreateEvent(NULL, TRUE, FALSE, NULL);
	thread->hDebugLoadDone = CreateEvent(NULL, FALSE, FALSE, NULL);
	thread->pidToDebug = pid;
	thread->hDebugThread = CreateThread(NULL, NULL, DebugThread, thread, NULL, &thread->hDebugThreadID);

	WaitForSingleObject(thread->hDebugLoadDone, INFINITE);
	if (WaitForSingleObject(thread->hDebugError, 0) != WAIT_OBJECT_0)
	{
		if (showSuccess)
		{
			TCHAR msg[1024];
			StringCbPrintf(msg, sizeof(msg), TEXT("Successfully injected into \"%s\"!"), PathFindFileName(thread->ret));
			MessageBox(hDlg, msg, TEXT("Info"), MB_ICONINFORMATION);
		}
		return true;
	}
	else
	{
		TCHAR msg[1024];
		StringCbPrintf(msg, sizeof(msg), TEXT("Failed to attach debugger!\n\n%s"), thread->ret);
		MessageBox(hDlg, msg, TEXT("Fatal Error"), MB_ICONERROR);

		ReleaseThreadContext(thread);
		return false;
	}
}

void DisplayError(HWND hDlg, DWORD errCode)
{
	TCHAR error[1024] = TEXT("");
	TCHAR msg[1024];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, errCode, 0, error, ARRAYSIZE(error), NULL);

	StringCbPrintf(msg, sizeof(msg), TEXT("Failed to open process!\n\n%s"), error);
	MessageBox(hDlg, msg, TEXT("Fatal Error"), MB_ICONERROR);
}

/*

---------- INJECTION ----------

*/

void InjectDLL(HWND hDlg, HANDLE hProcess, bool showSuccess = true)
{
	TCHAR dllFileName[MAX_PATH] = TEXT("");
	TCHAR exeFileName[MAX_PATH] = TEXT("");
	GetModuleFileName(NULL, dllFileName, ARRAYSIZE(dllFileName));
	if (!GetProcessImageFileName(hProcess, exeFileName, ARRAYSIZE(exeFileName)))
	{
		MessageBox(NULL, TEXT("Failed to inject into this process (try reselecting?)"), TEXT("Fatal Error"), MB_ICONERROR);
		return;
	}

	auto pos = 0;
	auto slashPos = pos;
	auto str = dllFileName;
	while (*str)
	{
		auto ch = *(str++);
		if (ch == L'\\')
			slashPos = pos;
		pos++;
	}
	dllFileName[slashPos + 1] = L'\0';
	StringCbCat(dllFileName, sizeof(dllFileName), INJECTOR_DLL);

	if (!PathFileExists(dllFileName))
	{
		TCHAR msg[1024];
		StringCbPrintf(msg, sizeof(msg), TEXT("Cannot find injector DLL \"%s\""), dllFileName);
		MessageBox(hDlg, msg, TEXT("Fatal Error"), MB_ICONERROR);
		return;
	}

	auto pDllFileName = (TCHAR*)VirtualAllocEx(hProcess, NULL, sizeof(dllFileName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!pDllFileName)
	{
		MessageBox(hDlg, TEXT("Failed to allocate memory for DLL file name (try reselecting?)!"), TEXT("Fatal Error"), MB_ICONERROR);
		return;
	}
	WriteProcessMemory(hProcess, pDllFileName, dllFileName, sizeof(dllFileName), NULL);

	DWORD threadID;
	auto hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibrary, pDllFileName, NULL, &threadID);
	if (!hThread)
	{
		MessageBox(hDlg, TEXT("Failed to create remote thread for injection!"), TEXT("Fatal Error"), MB_ICONERROR);
		goto cleanup;
	}
	WaitForSingleObject(hThread, INFINITE);

	if (showSuccess)
	{
		TCHAR msg[1024];
		StringCbPrintf(msg, sizeof(msg), TEXT("Successfully injected into \"%s\"!"), PathFindFileName(exeFileName));
		MessageBox(hDlg, msg, TEXT("Info"), MB_ICONINFORMATION);
	}

cleanup:
	VirtualFreeEx(hProcess, pDllFileName, NULL, MEM_RELEASE);
}

/*

---------- DIALOG FUNCTIONS ----------

*/

void RefreshProcessList(HWND listBox)
{
	auto currentPID = GetCurrentProcessId();

	DWORD processes[500];
	DWORD numProcesses;
	EnumProcesses(processes, sizeof(processes), &numProcesses);
	numProcesses /= sizeof(DWORD);

	SendMessage(listBox, LB_RESETCONTENT, NULL, NULL);
	for (DWORD i = 0; i < numProcesses; ++i)
	{
		auto pid = processes[i];
		if (pid == currentPID)
			continue;

		TCHAR fileName[MAX_PATH];
		size_t fileNameLen;
		auto procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (procHandle)
		{
			if (!ArchMatches(procHandle))
			{
				CloseHandle(procHandle);
				continue;
			}

			GetProcessImageFileName(procHandle, fileName, ARRAYSIZE(fileName));
			StringCbLength(fileName, sizeof(fileName), &fileNameLen);
			fileNameLen /= sizeof(*fileName);

			TCHAR name[MAX_PATH];
			TCHAR pidName[16];
			StringCbCopy(name, sizeof(name), PathFindFileName(fileName));
			StringCbCat(name, sizeof(name), TEXT(" ("));
			StringCbPrintf(pidName, sizeof(pidName), TEXT("%u"), pid);
			StringCbCat(name, sizeof(name), pidName);
			StringCbCat(name, sizeof(name), TEXT(")"));
			auto pos = SendMessage(listBox, LB_ADDSTRING, 0, (LPARAM)name);
			SendMessage(listBox, LB_SETITEMDATA, pos, (LPARAM)pid);
			CloseHandle(procHandle);
		}
	}
	SetFocus(listBox);
}

INT_PTR CALLBACK SettingsDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	auto hUseDebug = GetDlgItem(hDlg, IDC_USEDEBUG);

	switch (msg)
	{
	case WM_INITDIALOG:
	{
		Button_SetCheck(hUseDebug, debugInjection ? BST_CHECKED : BST_UNCHECKED);
		break;
	}
	case WM_CLOSE:
		goto close;
	case WM_COMMAND:
	{
		switch (wParam)
		{
		case ID_OK:
		{
			if (Button_GetCheck(hUseDebug) == BST_CHECKED)
			{
				if (sawDebugWarning)
				{
					debugInjection = true;
					goto close;
				}
				else if (MessageBox(hDlg,
					TEXT(
						"While debugger injection is generally better at catching exceptions, it is also generally less reliable to use than standard DLL injection, due to reasons like process stuttering and also doesn't play well with programs launched via Steam for instance (it has anti-debugging antics). If you insist on using debug injection, you must also make sure NoMoreCrashing stays open throughout the entirety of the program's duration, otherwise the crash handler gets removed.\n\nAre you sure you want to enable this?"
					), TEXT("Warning"), MB_ICONWARNING | MB_YESNO) == IDYES)
				{
					debugInjection = true;
					sawDebugWarning = true;
					goto close;
				}
				else
				{
					Button_SetCheck(hUseDebug, BST_UNCHECKED);
				}
			}
			else
			{
				debugInjection = false;
				goto close;
			}
			break;
		}
		case ID_CANCEL:
			goto close;
		}
		break;
	}
	}

	return 0;

close:
	EndDialog(hDlg, 0);
	return 0;
}

INT_PTR CALLBACK LaunchDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	auto hFileName = GetDlgItem(hDlg, IDC_FILENAME);
	auto hWorkingDir = GetDlgItem(hDlg, IDC_WORKINGDIR);

	auto setFilename = [](HWND hFileName, HWND hWorkingDir, const TCHAR* fileName)
	{
		Edit_SetText(hFileName, fileName);
		StringCbCopy(appFileName, sizeof(appFileName), fileName);

		TCHAR currentWorkingDir[MAX_PATH];
		Edit_GetText(hWorkingDir, currentWorkingDir, ARRAYSIZE(currentWorkingDir));
		if (!*currentWorkingDir)
		{
			auto start = fileName;
			auto end = PathFindFileName(fileName);
			auto dest = appWorkingDir;
			while (start < end)
				*(dest++) = *(start++);
			*dest = L'\0';

			Edit_SetText(hWorkingDir, appWorkingDir);
		}
	};

	switch (msg)
	{
	case WM_INITDIALOG:
	{
		DragAcceptFiles(hDlg, TRUE);

		Edit_SetText(hFileName, appFileName);
		Edit_SetText(hWorkingDir, appWorkingDir);
		break;
	}
	case WM_CLOSE:
		goto close;
	case WM_COMMAND:
	{
		switch (wParam)
		{
		case ID_OK:
		{
			Edit_GetText(hFileName, appFileName, ARRAYSIZE(appFileName));
			Edit_GetText(hWorkingDir, appWorkingDir, ARRAYSIZE(appWorkingDir));

			if (debugInjection)
			{
				if (AddDebugThread(hDlg, PID_LAUNCH_EXTERNAL, false))
					goto close;
			}
			else
			{
				STARTUPINFO startupInfo = {};
				startupInfo.cb = sizeof(startupInfo);
				PROCESS_INFORMATION processInfo;
				if (CreateProcess(NULL, appFileName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, appWorkingDir, &startupInfo, &processInfo))
				{
					if (ArchMatches(processInfo.hProcess))
					{
						InjectDLL(hDlg, processInfo.hProcess, false);
						ResumeThread(processInfo.hThread);
						CloseHandle(processInfo.hProcess);
						CloseHandle(processInfo.hThread);
						goto close;
					}
					else
					{
						TerminateProcess(processInfo.hProcess, 1);
						CloseHandle(processInfo.hProcess);
						CloseHandle(processInfo.hThread);
#ifdef _WIN64
						MessageBox(hDlg, TEXT("Incompatible architecture, you must run the 32-bit version of NoMoreCrashing to inject into this program."), TEXT("Architecture Mismatch"), MB_ICONERROR);
#else
						MessageBox(hDlg, TEXT("Incompatible architecture, you must run the 64-bit version of NoMoreCrashing to inject into this program."), TEXT("Architecture Mismatch"), MB_ICONERROR);
#endif
					}
				}
				else
				{
					DisplayError(hDlg, GetLastError());
				}
			}
			break;
		}
		case ID_CANCEL:
			goto close;
		case ID_BROWSEF:
		{
			TCHAR currentDir[MAX_PATH];
			GetCurrentDirectory(ARRAYSIZE(currentDir), currentDir);

			TCHAR fileName[MAX_PATH] = TEXT("");

			OPENFILENAME ofn;
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = hDlg;
			ofn.hInstance = hInst;
			ofn.lpstrFilter = TEXT("Applications\0*.exe;\0\0");
			ofn.lpstrCustomFilter = NULL;
			ofn.nMaxCustFilter = ofn.nFilterIndex = 0;
			ofn.lpstrFile = fileName;
			ofn.nMaxFile = ARRAYSIZE(fileName);
			ofn.lpstrFileTitle = NULL;
			ofn.nMaxFileTitle = NULL;
			ofn.lpstrInitialDir = currentDir;
			ofn.lpstrTitle = TEXT("Select a program to run");
			ofn.Flags = OFN_FILEMUSTEXIST | OFN_LONGNAMES;
			ofn.nFileOffset = ofn.nFileExtension = 0;
			ofn.lpstrDefExt = TEXT("exe");
			ofn.lCustData = NULL;
			ofn.lpfnHook = NULL;
			ofn.lpTemplateName = NULL;
			ofn.FlagsEx = 0;
			if (GetOpenFileName(&ofn))
				setFilename(hFileName, hWorkingDir, fileName);

			break;
		}
		case ID_BROWSEW:
		{
			TCHAR workingDir[MAX_PATH] = TEXT("");

			BROWSEINFO bi;
			bi.hwndOwner = hDlg;
			bi.pidlRoot = NULL;
			bi.pszDisplayName = workingDir;
			bi.lpszTitle = TEXT("Select a working directory");
			bi.ulFlags = BIF_EDITBOX;
			bi.lpfn = NULL;
			bi.lParam = NULL;
			bi.iImage = 0;
			if (SHBrowseForFolder(&bi))
			{
				Edit_SetText(hWorkingDir, workingDir);
				StringCbCopy(appWorkingDir, sizeof(appWorkingDir), workingDir);
			}
			break;
		}
		}
		break;
	}
	case WM_DROPFILES:
	{
		auto hDrop = (HDROP)wParam;

		TCHAR dragFileName[MAX_PATH];
		if (DragQueryFile(hDrop, 0, dragFileName, ARRAYSIZE(dragFileName)))
			setFilename(hFileName, hWorkingDir, dragFileName);

		DragFinish(hDrop);
		break;
	}
	}

	return 0;

close:
	Edit_GetText(hFileName, appFileName, ARRAYSIZE(appFileName));
	Edit_GetText(hWorkingDir, appWorkingDir, ARRAYSIZE(appWorkingDir));
	EndDialog(hDlg, 0);
	return 0;
}

INT_PTR CALLBACK MainDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	auto hArch = GetDlgItem(hDlg, IDC_RUNARCH);
	auto hProgramList = GetDlgItem(hDlg, IDC_PROGLIST);

	switch (msg)
	{
	case WM_INITDIALOG:
	{
		SetWindowPos(hDlg, NULL, 128, 128, NULL, NULL, SWP_NOSIZE);

#ifdef _WIN64
		SetWindowText(hArch, TEXT("64-bit version\n(only shows 64-bit processes)"));
#else
		SetWindowText(hArch, TEXT("32-bit version\n(only shows 32-bit processes)"));
#endif
		RefreshProcessList(hProgramList);
		break;
	}
	case WM_CLOSE:
		goto close;
	case WM_COMMAND:
	{
		switch (wParam)
		{
		case ID_INJECT:
		{
			auto selIndex = SendMessage(hProgramList, LB_GETCURSEL, NULL, NULL);
			if (selIndex != LB_ERR)
			{
				auto pid = (DWORD)SendMessage(hProgramList, LB_GETITEMDATA, selIndex, NULL);
				if (debugInjection)
				{
					AddDebugThread(hDlg, pid);
				}
				else
				{
					auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
					if (hProcess)
					{
						InjectDLL(hDlg, hProcess);
						CloseHandle(hProcess);
					}
					else
					{
						DisplayError(hDlg, GetLastError());
					}
				}
			}
			else
			{
				MessageBox(hDlg, TEXT("Please select a process to inject."), TEXT("Fatal Error"), MB_ICONERROR);
			}
			break;
		}
		case ID_LAUNCH:
		{
			DialogBox(hInst, MAKEINTRESOURCE(IDD_LAUNCH), hDlg, LaunchDialogProc);
			break;
		}
		case ID_CANCEL:
			goto close;
		case ID_REFRESH:
		{
			RefreshProcessList(hProgramList);
			break;
		}
		case ID_SETTINGS:
		{
			DialogBox(hInst, MAKEINTRESOURCE(IDD_SETTINGS), hDlg, SettingsDialogProc);
			break;
		}
		}
		break;
	}
	}

	return 0;

close:
	EndDialog(hDlg, 0);
	return 0;
}


/*

---------- ENTRY POINT ----------

*/

int WINAPI WinMain(HINSTANCE hInstMain, HINSTANCE, LPSTR, INT)
{
	hInst = hInstMain;
	DialogBox(hInst, MAKEINTRESOURCE(IDD_MAIN), NULL, MainDialogProc);
	return 0;
}