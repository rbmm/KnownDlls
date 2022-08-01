#include "stdafx.h"

_NT_BEGIN

#include "wlog.h"

void TryOpen(WLog& log, PVOID buf)
{
	NTSTATUS status;

	union {
		PVOID pv;
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	pv = buf;
	ULONG NextEntryOffset = 0;

	do 
	{
		pb += NextEntryOffset;

		HANDLE hProcess;

		CLIENT_ID ClientId = { pspi->UniqueProcessId };

		if (ClientId.UniqueProcess)
		{
			static OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };

			status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, const_cast<POBJECT_ATTRIBUTES>(&zoa), &ClientId);
			
			log(L"%08x %08x %wZ", status, ClientId.UniqueProcess, &pspi->ImageName);

			if (0 <= status || 0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, const_cast<POBJECT_ATTRIBUTES>(&zoa), &ClientId))
			{
				ULONG cb;
				PS_PROTECTION ps;
				
				if (0 <= NtQueryInformationProcess(hProcess, ProcessProtectionInformation, &ps, sizeof(ps), &cb))
				{
					if (ps.Type) log( L" [%x.%x]", ps.Type, ps.Signer);
				}
				
				if ((cb = log._cch() * sizeof(WCHAR)) > 0x100)
				{
					POBJECT_NAME_INFORMATION pCmdLine = (POBJECT_NAME_INFORMATION)(
						((ULONG_PTR)log._buf() + 0x3f + __alignof(OBJECT_NAME_INFORMATION)) & ~(__alignof(OBJECT_NAME_INFORMATION) - 1)
						);

					if (0 <= NtQueryInformationProcess(hProcess, ProcessCommandLineInformation, pCmdLine, 
						cb - 0x40 - __alignof(OBJECT_NAME_INFORMATION), &cb))
					{
						if (pCmdLine->Name.Length > 0x100)
						{
							pCmdLine->Name.Length = 0x100;
						}

						log( L"  >>  %wZ", &pCmdLine->Name);
					}
				}

				NtClose(hProcess);
			}

			log << L"\r\n";
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);
}

void Demo(WLog& log)
{
	NTSTATUS status;
	ULONG cb = 0x40000;

	do 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (PBYTE buf = new BYTE[cb += PAGE_SIZE])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				TryOpen(log, buf);
			}

			delete [] buf;
		}

	} while(status == STATUS_INFO_LENGTH_MISMATCH);
}

HANDLE g_hActCtx;
BOOLEAN g_bActCtxValid;

void WINAPI ep(ULONG_PTR Cookie)
{
	BOOL bActivated = FALSE;

	if (!g_bActCtxValid || (bActivated = ActivateActCtx(g_hActCtx, &Cookie)))
	{
		WLog log;
		if (!log.Init(0x100000))
		{
			if (HWND hwnd = CreateWindowExW(0, WC_EDIT, L"PP Query", WS_OVERLAPPEDWINDOW|WS_HSCROLL|WS_VSCROLL|ES_MULTILINE,
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

				Demo(log);

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

		if (bActivated) DeactivateActCtx(0, Cookie);
	}

	ExitProcess(0);
}

#ifdef _AMD64_
#define EpReg Rcx
#else
#define EpReg Eax
#endif

BOOLEAN WINAPI DllMain( HMODULE hDllHandle, DWORD dwReason, ULONG_PTR AddressOfEntryPoint )
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		// do Sleep(500); while (!IsDebuggerPresent()); __debugbreak();
		g_bActCtxValid = GetCurrentActCtx(&g_hActCtx) != FALSE;
		break;

	case DLL_PROCESS_DETACH:
		if (g_bActCtxValid) ReleaseActCtx(g_hActCtx);
		[[fallthrough]];
	default:
		return TRUE;
	}

	DisableThreadLibraryCalls(hDllHandle);

	PWSTR psz = GetCommandLineW();

	if (*psz == '\n' && (dwReason = wcstoul(psz + 1, &psz, 16)) && !*psz)
	{
		if (HANDLE hThread = OpenThread(THREAD_ALERT, FALSE, dwReason))
		{
			ZwAlertThread(hThread);
			NtClose(hThread);
		}

		if (hDllHandle = GetModuleHandleW(0))
		{
			if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(hDllHandle))
			{
				AddressOfEntryPoint = (ULONG_PTR)hDllHandle + pinth->OptionalHeader.AddressOfEntryPoint;

				CONTEXT ContextRecord;
				RtlCaptureContext(&ContextRecord);
				PNT_TIB Tib = (PNT_TIB)NtCurrentTeb();

				union {
					ULONG_PTR up;
					PCONTEXT pCtx;
				};

				up = ((ULONG_PTR)Tib->StackBase - sizeof(CONTEXT) + __alignof(CONTEXT) - 1) & ~(__alignof(CONTEXT) - 1);

				if (pCtx > &ContextRecord)
				{
					do 
					{
						if (pCtx->EpReg == AddressOfEntryPoint && 
							pCtx->SegCs == ContextRecord.SegCs &&
							pCtx->SegSs == ContextRecord.SegSs)
						{
							pCtx->Rcx = (ULONG_PTR)ep;
							break;
						}

					} while ((up -= __alignof(CONTEXT)) > (ULONG_PTR)_AddressOfReturnAddress());
				}
			}
		}
	}

	return TRUE;
}

_NT_END
