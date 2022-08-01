#include "stdafx.h"

_NT_BEGIN

#include "token.h"

const SECURITY_QUALITY_OF_SERVICE sqos = {
	sizeof (sqos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE
};

const OBJECT_ATTRIBUTES oa_sqos = { sizeof(oa_sqos), 0, 0, 0, 0, const_cast<SECURITY_QUALITY_OF_SERVICE*>(&sqos) };
const TOKEN_PRIVILEGES tp_Debug = { 1, { { { SE_DEBUG_PRIVILEGE }, SE_PRIVILEGE_ENABLED } } };

NTSTATUS SetToken(_In_opt_ HANDLE hToken)
{
	return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
}

NTSTATUS AdjustPrivileges(_In_ const TOKEN_PRIVILEGES* ptp)
{
	NTSTATUS status;
	HANDLE hToken, hNewToken;

	if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE, &hToken)))
	{
		status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE, 
			const_cast<OBJECT_ATTRIBUTES*>(&oa_sqos), FALSE, TokenImpersonation, &hNewToken);

		NtClose(hToken);

		if (0 <= status)
		{
			if (STATUS_SUCCESS == (status = NtAdjustPrivilegesToken(hNewToken, FALSE, 
				const_cast<PTOKEN_PRIVILEGES>(ptp), 0, 0, 0)))
			{
				status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hNewToken, sizeof(hNewToken));
			}

			NtClose(hNewToken);
		}
	}

	return status;
}

NTSTATUS TOKENS::GetTokens(_In_ PVOID buf, _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor, _In_ PGENERIC_MAPPING GenericMapping )
{
	NTSTATUS status, AccessStatus;

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

		HANDLE hProcess, hToken, ClientToken;

		CLIENT_ID ClientId = { pspi->UniqueProcessId };

		if (ClientId.UniqueProcess)
		{
			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, 
				const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), &ClientId))
			{
				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtDuplicateToken(hToken, 
						TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY|TOKEN_IMPERSONATE|TOKEN_DUPLICATE, 
						const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), FALSE, TokenImpersonation, &ClientToken);

					NtClose(hToken);

					if (0 <= status)
					{
						PRIVILEGE_SET PrivilegeSet;
						ULONG GrantedAccess, PrivilegeSetLength = sizeof(PrivilegeSet);

						if (STATUS_SUCCESS == (status = NtAdjustPrivilegesToken(ClientToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(RequiredSet), 0, 0, 0)))
						{
							if (0 <= (status = NtAccessCheck(pSecurityDescriptor, ClientToken, DIRECTORY_CREATE_OBJECT, 
								GenericMapping, &PrivilegeSet, &PrivilegeSetLength, &GrantedAccess, &AccessStatus)) &&
								0 <= (status = AccessStatus) &&
								0 <= (status = NtDuplicateToken(ClientToken, 
								TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY|TOKEN_DUPLICATE|TOKEN_ADJUST_SESSIONID|TOKEN_ADJUST_DEFAULT, 
								0, FALSE, TokenPrimary, &hToken)))
							{
								hPrimaryToken = hToken;
								hImpersonationToken = ClientToken;

								return STATUS_SUCCESS;
							}
						}

						NtClose(ClientToken);

					}
				}
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return STATUS_NOT_FOUND;
}

NTSTATUS TOKENS::GetTokens(_In_ PSECURITY_DESCRIPTOR pSecurityDescriptor, _In_ PGENERIC_MAPPING GenericMapping)
{
	NTSTATUS status = AdjustPrivileges(&tp_Debug);

	if (status == STATUS_SUCCESS)
	{
		ULONG cb = 0x40000;

		do 
		{
			status = STATUS_INSUFFICIENT_RESOURCES;

			if (PBYTE buf = new BYTE[cb += PAGE_SIZE])
			{
				if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
				{
					status = GetTokens(buf, pSecurityDescriptor, GenericMapping);

					if (status == STATUS_INFO_LENGTH_MISMATCH)
					{
						status = STATUS_UNSUCCESSFUL;
					}
				}

				delete [] buf;
			}

		} while(status == STATUS_INFO_LENGTH_MISMATCH);
	}

	return status;
}

extern volatile const UCHAR guz = 0;

NTSTATUS TOKENS::Get(_In_ PCWSTR DirectoryName)
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, DirectoryName);

	NTSTATUS status;
	HANDLE DirectoryHandle;

	if (0 <= (status = ZwOpenDirectoryObject(&DirectoryHandle, READ_CONTROL, &oa)))
	{
		PVOID stack = alloca(guz);

		ULONG cb = 0, rcb = 0x40;

		union {
			PVOID buf = 0;
			PSECURITY_DESCRIPTOR pSecurityDescriptor;
		};

		do 
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			status = NtQuerySecurityObject(DirectoryHandle, 
				DACL_SECURITY_INFORMATION|
				LABEL_SECURITY_INFORMATION|
				OWNER_SECURITY_INFORMATION|
				GROUP_SECURITY_INFORMATION|
				PROCESS_TRUST_LABEL_SECURITY_INFORMATION,
				pSecurityDescriptor, cb, &rcb);

		} while (status == STATUS_BUFFER_TOO_SMALL);

		NtClose(DirectoryHandle);

		if (0 <= status)
		{
			static const GENERIC_MAPPING GenericMapping = {
				DIRECTORY_QUERY, 
				DIRECTORY_CREATE_OBJECT|DIRECTORY_CREATE_SUBDIRECTORY, 
				DIRECTORY_TRAVERSE,
				DIRECTORY_ALL_ACCESS
			};

			status = GetTokens(pSecurityDescriptor, const_cast<PGENERIC_MAPPING>(&GenericMapping));
		}
	}

	return status;
}

_NT_END