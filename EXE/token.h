#pragma once

extern volatile const UCHAR guz;

NTSTATUS SetToken(_In_opt_ HANDLE hToken = 0);

NTSTATUS AdjustPrivileges(_In_ const TOKEN_PRIVILEGES* ptp);

struct TOKENS 
{
	const TOKEN_PRIVILEGES* RequiredSet;
	HANDLE hImpersonationToken = 0;
	HANDLE hPrimaryToken = 0;

	TOKENS(const TOKEN_PRIVILEGES* RequiredSet) : RequiredSet(RequiredSet)
	{
	}

	~TOKENS()
	{
		HANDLE hToken;

		if (hToken = hPrimaryToken)
		{
			NtClose(hToken);
		}

		if (hToken = hImpersonationToken)
		{
			NtClose(hToken);
		}
	}

	NTSTATUS Get(_In_ PCWSTR DirectoryName);

private:

	NTSTATUS GetTokens(
		_In_ PVOID buf,
		_In_ PSECURITY_DESCRIPTOR pSecurityDescriptor, 
		_In_ PGENERIC_MAPPING GenericMapping
		);

	NTSTATUS GetTokens(
		_In_ PSECURITY_DESCRIPTOR pSecurityDescriptor, 
		_In_ PGENERIC_MAPPING GenericMapping
		);
};

