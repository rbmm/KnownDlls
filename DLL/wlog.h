#pragma once

class WLog
{
	PVOID _BaseAddress;
	ULONG _RegionSize, _Ptr;

public:
	PWSTR _buf()
	{
		return (PWSTR)((PBYTE)_BaseAddress + _Ptr);
	}

	ULONG _cch()
	{
		return (_RegionSize - _Ptr) / sizeof(WCHAR);
	}

	void operator >> (HWND hwnd);

	ULONG Init(SIZE_T RegionSize);
	
	~WLog();

	WLog(WLog&&) = delete;
	WLog(WLog&) = delete;
	WLog(): _BaseAddress(0) {  }

	operator PCWSTR()
	{
		return (PCWSTR)_BaseAddress;
	}

	WLog& operator << (PCWSTR str);

	WLog& operator ()(PCWSTR format, ...);

	WLog& operator[](HRESULT dwError);
};
