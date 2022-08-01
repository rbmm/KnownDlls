#include "stdafx.h"

_NT_BEGIN

PVOID NTAPI AddressInSectionTable ( PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva )
{
	return NtHeaders ? RtlAddressInSectionTable(NtHeaders, Base, Rva) : (PBYTE)Base + Rva;
}

HRESULT CreateExportDef(PVOID hmod, BOOLEAN MappedAsImage)
{
	if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(hmod))
	{
		if (MappedAsImage)
		{
			pinth = 0;
		}

		ULONG size;
		if (PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(hmod, MappedAsImage, IMAGE_DIRECTORY_ENTRY_EXPORT, &size))
		{
			if (DWORD NumberOfNames = pied->NumberOfNames)
			{
				DbgPrint("EXPORTS\n");

				if (PULONG AddressOfNames = (PULONG)AddressInSectionTable(pinth, hmod, pied->AddressOfNames))
				{
					if (PUSHORT AddressOfNameOrdinals = (PUSHORT)AddressInSectionTable(pinth, hmod, pied->AddressOfNameOrdinals))
					{
						PULONG AddressOfFunctions = (PULONG)AddressInSectionTable(pinth, hmod, pied->AddressOfFunctions);

						if (!AddressOfFunctions)
						{
							return E_FAIL;
						}

						DWORD NumberOfFunctions = pied->NumberOfFunctions;

						if (NumberOfFunctions < NumberOfNames)
						{
							return E_FAIL;
						}

						ULONG cb = (NumberOfFunctions + 7) >> 3;
						PLONG bits = (PLONG)alloca(cb);

						RtlZeroMemory(bits, cb);

						PVOID pv;
						ULONG Base = pied->Base;

						do 
						{
							if (PCSTR Name = (PCSTR)AddressInSectionTable(pinth, hmod, *AddressOfNames++))
							{
								ULONG i = *AddressOfNameOrdinals++;

								if (i >= NumberOfFunctions)
								{
									return E_FAIL;
								}

								if (!(pv = AddressInSectionTable(pinth, hmod, AddressOfFunctions[i])))
								{
									return E_FAIL;
								}

								_bittestandset(bits, i);

								DbgPrint("%s = \\\\?\\global\\globalroot\\systemroot\\system32\\EventAggregation.%s\n", Name, Name);
								//DbgPrint("void %s() {}\n", Name);
							}
							else
							{
								return E_FAIL;
							}

						} while (--NumberOfNames);

						AddressOfFunctions += NumberOfFunctions;
						do 
						{
							ULONG rva = *--AddressOfFunctions;

							if (!_bittest(bits, --NumberOfFunctions))
							{
								if (!rva)
								{
									continue;
								}

								if (!(pv = AddressInSectionTable(pinth, hmod, rva)))
								{
									return E_FAIL;
								}

								DbgPrint("@%u = \\\\?\\global\\globalroot\\systemroot\\system32\\EventAggregation.#%u @%u NONAME\n", 
									Base + NumberOfFunctions, Base + NumberOfFunctions, Base + NumberOfFunctions);
								//DbgPrint("void __%u(){}\n", Base + NumberOfFunctions);
							}

						} while (NumberOfFunctions);

						return S_OK;
					}
				}
			}
		}
	}

	return E_FAIL;
}

HRESULT CreateExportDef(PCWSTR lpLibFileName)
{
	if (HMODULE hmod = LoadLibraryExW(lpLibFileName, 0, LOAD_LIBRARY_AS_DATAFILE))
	{
		PVOID base = PAGE_ALIGN(hmod);
		HRESULT hr = CreateExportDef(base, base == hmod);

		FreeLibrary(hmod);

		return hr;
	}

	return GetLastHr();
}

_NT_END

