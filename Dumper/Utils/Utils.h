#pragma once

#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <functional>


/* Credits: https://en.cppreference.com/w/cpp/string/byte/tolower */
inline std::string str_tolower(std::string S)
{
	std::transform(S.begin(), S.end(), S.begin(), [](unsigned char C) { return std::tolower(C); });
	return S;
}

template<typename CharType>
inline int32_t StrlenHelper(const CharType* Str)
{
	if constexpr (std::is_same<CharType, char>())
	{
		return strlen(Str);
	}
	else
	{
		return wcslen(Str);
	}
}

template<typename CharType>
inline bool StrnCmpHelper(const CharType* Left, const CharType* Right, size_t NumCharsToCompare)
{
	if constexpr (std::is_same<CharType, char>())
	{
		return strncmp(Left, Right, NumCharsToCompare) == 0;
	}
	else
	{
		return wcsncmp(Left, Right, NumCharsToCompare) == 0;
	}
}

namespace ASMUtils
{
	/* See IDA or https://c9x.me/x86/html/file_module_x86_id_147.html for reference on the jmp opcode */
	inline bool Is32BitRIPRelativeJump(uintptr_t Address)
	{
		return Address && *reinterpret_cast<uint8_t*>(Address) == 0xE9; /* 48 for jmp, FF for "RIP relative" -- little endian */
	}

	inline uintptr_t Resolve32BitRIPRelativeJumpTarget(uintptr_t Address)
	{
		constexpr int32_t InstructionSizeBytes = 0x5;
		constexpr int32_t InstructionImmediateDisplacementOffset = 0x1;

		const int32_t Offset = *reinterpret_cast<int32_t*>(Address + InstructionImmediateDisplacementOffset);

		/* Add the InstructionSizeBytes because offsets are relative to the next instruction. */
		return Address + InstructionSizeBytes + Offset;
	}

	/* See https://c9x.me/x86/html/file_module_x86_id_147.html */
	inline uintptr_t Resolve32BitRegisterRelativeJump(uintptr_t Address)
	{
		/*
		* 48 FF 25 C1 10 06 00     jmp QWORD [rip+0x610c1]
		*
		* 48 FF 25 <-- Information on the instruction [jump, relative, rip]
		* C1 10 06 00 <-- 32-bit Offset relative to the address coming **after** these instructions (+ 7) [if 48 had hte address 0x0 the offset would be relative to address 0x7]
		*/

		return ((Address + 7) + *reinterpret_cast<int32_t*>(Address + 3));
	}

	inline uintptr_t Resolve32BitSectionRelativeCall(uintptr_t Address)
	{
		/* Same as in Resolve32BitRIPRelativeJump, but instead of a jump we resolve a call, with one less instruction byte */
		return ((Address + 6) + *reinterpret_cast<int32_t*>(Address + 2));
	}

	inline uintptr_t Resolve32BitRelativeCall(uintptr_t Address)
	{
		/* Same as in Resolve32BitRIPRelativeJump, but instead of a jump we resolve a non-relative call, with two less instruction byte */
		return ((Address + 5) + *reinterpret_cast<int32_t*>(Address + 1));
	}

	inline uintptr_t Resolve32BitRelativeMove(uintptr_t Address)
	{
		/* Same as in Resolve32BitRIPRelativeJump, but instead of a jump we resolve a relative mov */
		return ((Address + 7) + *reinterpret_cast<int32_t*>(Address + 3));
	}

	inline uintptr_t Resolve32BitRelativeLea(uintptr_t Address)
	{
		/* Same as in Resolve32BitRIPRelativeJump, but instead of a jump we resolve a relative lea */
		return ((Address + 7) + *reinterpret_cast<int32_t*>(Address + 3));
	}
}


struct CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
};

struct TEB
{
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	struct PEB* ProcessEnvironmentBlock;
};

struct PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	BYTE MoreFunnyPadding[0x3];
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	BYTE MoreFunnyPadding2[0x7];
	HANDLE ShutdownThreadId;
};

struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	BYTE ManuallyAddedPaddingCauseTheCompilerIsStupid[0x4]; // It doesn't 0x8 byte align the pointers properly 
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
};

struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	BYTE MoreStupidCompilerPaddingYay[0x4];
	PWCH Buffer;
};

struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	//union
	//{
	//	LIST_ENTRY InInitializationOrderLinks;
	//	LIST_ENTRY InProgressLinks;
	//};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	BYTE MoreStupidCompilerPaddingYay[0x4];
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
}; 

inline _TEB* _NtCurrentTeb()
{
	return reinterpret_cast<struct _TEB*>(__readgsqword(((LONG)__builtin_offsetof(NT_TIB, Self))));
}

inline PEB* GetPEB()
{
	return reinterpret_cast<TEB*>(_NtCurrentTeb())->ProcessEnvironmentBlock;
}

inline LDR_DATA_TABLE_ENTRY* GetModuleLdrTableEntry(const char* SearchModuleName)
{
	PEB* Peb = GetPEB();
	PEB_LDR_DATA* Ldr = Peb->Ldr;

	int NumEntriesLeft = Ldr->Length;

	for (LIST_ENTRY* P = Ldr->InMemoryOrderModuleList.Flink; P && NumEntriesLeft-- > 0; P = P->Flink)
	{
		LDR_DATA_TABLE_ENTRY* Entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(P);

		std::wstring WideModuleName(Entry->BaseDllName.Buffer, Entry->BaseDllName.Length >> 1);
		std::string ModuleName = std::string(WideModuleName.begin(), WideModuleName.end());

		if (str_tolower(ModuleName) == str_tolower(SearchModuleName))
			return Entry;
	}

	return nullptr;
}

inline uintptr_t GetModuleBase(const char* const ModuleName = nullptr)
{
	if (ModuleName == nullptr)
		return reinterpret_cast<uintptr_t>(GetPEB()->ImageBaseAddress);

	return reinterpret_cast<uintptr_t>(GetModuleLdrTableEntry(ModuleName)->DllBase);
}

inline std::pair<uintptr_t, uintptr_t> GetImageBaseAndSize(const char* const ModuleName = nullptr)
{
	uintptr_t ImageBase = GetModuleBase(ModuleName);
	PIMAGE_NT_HEADERS NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(ImageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase)->e_lfanew);

	return { ImageBase, NtHeader->OptionalHeader.SizeOfImage };
}

/* Returns the base address of th section and it's size */
inline std::pair<uintptr_t, DWORD> GetSectionByName(uintptr_t ImageBase, const std::string& ReqestedSectionName)
{
	if (ImageBase == 0)
		return { NULL, 0 };

	const PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
	const PIMAGE_NT_HEADERS NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(ImageBase + DosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(NtHeaders);

	DWORD TextSize = 0;

	for (int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER& CurrentSection = Sections[i];

		std::string SectionName = reinterpret_cast<const char*>(CurrentSection.Name);

		if (SectionName == ReqestedSectionName)
			return { (ImageBase + CurrentSection.VirtualAddress), CurrentSection.Misc.VirtualSize };
	}

	return { NULL, 0 };
}

inline uintptr_t GetOffset(const uintptr_t Address)
{
	static uintptr_t ImageBase = 0x0;

	if (ImageBase == 0x0)
		ImageBase = GetModuleBase();

	return Address > ImageBase ? (Address - ImageBase) : 0x0;
}

inline uintptr_t GetOffset(const void* Address)
{
	return GetOffset(reinterpret_cast<const uintptr_t>(Address));
}

inline bool IsInAnyModules(const uintptr_t Address)
{
	PEB* Peb = GetPEB();
	PEB_LDR_DATA* Ldr = Peb->Ldr;

	int NumEntriesLeft = Ldr->Length;

	for (LIST_ENTRY* P = Ldr->InMemoryOrderModuleList.Flink; P && NumEntriesLeft-- > 0; P = P->Flink)
	{
		LDR_DATA_TABLE_ENTRY* Entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(P);

		if (reinterpret_cast<void*>(Address) > Entry->DllBase && reinterpret_cast<void*>(Address) < ((PCHAR)Entry->DllBase + Entry->SizeOfImage))
			return true;
	}

	return false;
}

// The processor (x86-64) only translates 52bits (or 57 bits) of a virtual address into a physical address and the unused bits need to be all 0 or all 1.
inline bool IsValidVirtualAddress(const uintptr_t Address)
{
	constexpr uint64_t BitMask = 0b1111'1111ull << 56;

	return (Address & BitMask) == BitMask || (Address & BitMask) == 0x0;
}

inline bool IsInProcessRange(const uintptr_t Address)
{
	const auto [ImageBase, ImageSize] = GetImageBaseAndSize();

	if (Address >= ImageBase && Address < (ImageBase + ImageSize))
		return true;

	return IsInAnyModules(Address);
}

inline bool IsInProcessRange(const void* Address)
{
	return IsInProcessRange(reinterpret_cast<const uintptr_t>(Address));
}
inline bool IsBadReadPtr(const void* Ptr)
{
	if(!IsValidVirtualAddress(reinterpret_cast<const uintptr_t>(Ptr)))
		return true;

	MEMORY_BASIC_INFORMATION Mbi;

	if (VirtualQuery(Ptr, &Mbi, sizeof(Mbi)))
	{
		constexpr DWORD AccessibleMask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
		constexpr DWORD InaccessibleMask = (PAGE_GUARD | PAGE_NOACCESS);

		return !(Mbi.Protect & AccessibleMask) || (Mbi.Protect & InaccessibleMask);
	}

	return true;
};

inline bool IsBadReadPtr(const uintptr_t Ptr)
{
	return IsBadReadPtr(reinterpret_cast<const void*>(Ptr));
}

inline void* GetModuleAddress(const char* SearchModuleName)
{
	LDR_DATA_TABLE_ENTRY* Entry = GetModuleLdrTableEntry(SearchModuleName);

	if (Entry)
		return Entry->DllBase;

	return nullptr;
}

/* Gets the address at which a pointer to an imported function is stored */
inline PIMAGE_THUNK_DATA GetImportAddress(uintptr_t ModuleBase, const char* ModuleToImportFrom, const char* SearchFunctionName)
{
	/* Get the module importing the function */
	PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBase);

	if (ModuleBase == 0x0 || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	PIMAGE_NT_HEADERS NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(ModuleBase + reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBase)->e_lfanew);

	if (!NtHeader)
		return nullptr;

	PIMAGE_IMPORT_DESCRIPTOR ImportTable = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ModuleBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	//std::cout << "ModuleName: " << (SearchModuleName ? SearchModuleName : "Default") << std::endl;

	/* Loop all modules and if we found the right one, loop all imports to get the one we need */
	for (PIMAGE_IMPORT_DESCRIPTOR Import = ImportTable; Import && Import->Characteristics != 0x0; Import++)
	{
		if (Import->Name == 0xFFFF)
			continue;

		const char* Name = reinterpret_cast<const char*>(ModuleBase + Import->Name);

		//std::cout << "Name: " << str_tolower(Name) << std::endl;

		if (str_tolower(Name) != str_tolower(ModuleToImportFrom))
			continue;

		PIMAGE_THUNK_DATA NameThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(ModuleBase + Import->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FuncThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(ModuleBase + Import->FirstThunk);

		while (!IsBadReadPtr(NameThunk)
			&& !IsBadReadPtr(FuncThunk)
			&& !IsBadReadPtr(ModuleBase + NameThunk->u1.AddressOfData)
			&& !IsBadReadPtr(FuncThunk->u1.AddressOfData))
		{
			/*
			* A functin might be imported using the Ordinal (Index) of this function in the modules export-table
			*
			* The name could probably be retrieved by looking up this Ordinal in the Modules export-name-table
			*/
			if ((NameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) != 0) // No ordinal
			{
				NameThunk++;
				FuncThunk++;
				continue; // Maybe Handle this in the future
			}

			/* Get Import data for this function */
			PIMAGE_IMPORT_BY_NAME NameData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ModuleBase + NameThunk->u1.ForwarderString);
			PIMAGE_IMPORT_BY_NAME FunctionData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(FuncThunk->u1.AddressOfData);

			//std::cout << "IMPORT: " << std::string(NameData->Name) << std::endl;

			if (std::string(NameData->Name) == SearchFunctionName)
				return FuncThunk;

			NameThunk++;
			FuncThunk++;
		}
	}

	return nullptr;
}

/* Gets the address at which a pointer to an imported function is stored */
inline PIMAGE_THUNK_DATA GetImportAddress(const char* SearchModuleName, const char* ModuleToImportFrom, const char* SearchFunctionName)
{
	const uintptr_t SearchModule = SearchModuleName ? reinterpret_cast<uintptr_t>(GetModuleAddress(SearchModuleName)) : GetModuleBase();

	return GetImportAddress(SearchModule, ModuleToImportFrom, SearchFunctionName);
}

/* Finds the import for a funciton and returns the address of the function from the imported module */
inline void* GetAddressOfImportedFunction(const char* SearchModuleName, const char* ModuleToImportFrom, const char* SearchFunctionName)
{
	PIMAGE_THUNK_DATA FuncThunk = GetImportAddress(SearchModuleName, ModuleToImportFrom, SearchFunctionName);

	if (!FuncThunk)
		return nullptr;

	return reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(FuncThunk->u1.AddressOfData);
}

inline void* GetAddressOfImportedFunctionFromAnyModule(const char* ModuleToImportFrom, const char* SearchFunctionName)
{
	PEB* Peb = GetPEB();
	PEB_LDR_DATA* Ldr = Peb->Ldr;

	int NumEntriesLeft = Ldr->Length;

	for (LIST_ENTRY* P = Ldr->InMemoryOrderModuleList.Flink; P && NumEntriesLeft-- > 0; P = P->Flink)
	{
		LDR_DATA_TABLE_ENTRY* Entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(P);

		PIMAGE_THUNK_DATA Import = GetImportAddress(reinterpret_cast<uintptr_t>(Entry->DllBase), ModuleToImportFrom, SearchFunctionName);

		if (Import)
			return reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(Import->u1.AddressOfData);
	}

	return nullptr;
}

/* Gets the address of an exported function */
inline void* GetExportAddress(const char* SearchModuleName, const char* SearchFunctionName)
{
	/* Get the module the function was exported from */
	uintptr_t ModuleBase = reinterpret_cast<uintptr_t>(GetModuleAddress(SearchModuleName));
	PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBase);

	if (ModuleBase == 0x0 || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	PIMAGE_NT_HEADERS NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(ModuleBase + reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBase)->e_lfanew);

	if (!NtHeader)
		return nullptr;

	/* Get the table of functions exported by the module */
	PIMAGE_EXPORT_DIRECTORY ExportTable = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(ModuleBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	const DWORD* NameOffsets = reinterpret_cast<const DWORD*>(ModuleBase + ExportTable->AddressOfNames);
	const DWORD* FunctionOffsets = reinterpret_cast<const DWORD*>(ModuleBase + ExportTable->AddressOfFunctions);

	const WORD* Ordinals = reinterpret_cast<const WORD*>(ModuleBase + ExportTable->AddressOfNameOrdinals);

	/* Iterate all names and return the function if the name matches what we're looking for */
	for (int i = 0; i < ExportTable->NumberOfFunctions; i++)
	{
		const WORD NameIndex = Ordinals[i];
		const char* Name = reinterpret_cast<const char*>(ModuleBase + NameOffsets[NameIndex]);

		if (strcmp(SearchFunctionName, Name) == 0)
			return reinterpret_cast<void*>(ModuleBase + FunctionOffsets[i]);
	}

	return nullptr;
}

inline void* FindPatternInRange(std::vector<int>&& Signature, const uint8_t* Start, uintptr_t Range, bool bRelative = false, uint32_t Offset = 0, int SkipCount = 0)
{
	const auto PatternLength = Signature.size();
	const auto PatternBytes = Signature.data();

	for (int i = 0; i < (Range - PatternLength); i++)
	{
		bool bFound = true;
		int CurrentSkips = 0;

		for (auto j = 0ul; j < PatternLength; ++j)
		{
			if (Start[i + j] != PatternBytes[j] && PatternBytes[j] != -1)
			{
				bFound = false;
				break;
			}
		}
		if (bFound)
		{
			if (CurrentSkips != SkipCount)
			{
				CurrentSkips++;
				continue;
			}

			uintptr_t Address = uintptr_t(Start + i);
			if (bRelative)
			{
				if (Offset == -1)
					Offset = PatternLength;

				Address = ((Address + Offset + 4) + *reinterpret_cast<int32_t*>(Address + Offset));
			}
			return reinterpret_cast<void*>(Address);
		}
	}

	return nullptr;
}

inline void* FindPatternInRange(const char* Signature, const uint8_t* Start, uintptr_t Range, bool bRelative = false, uint32_t Offset = 0)
{
	static auto patternToByte = [](const char* pattern) -> std::vector<int>
	{
		auto Bytes = std::vector<int>{};
		const auto Start = const_cast<char*>(pattern);
		const auto End = const_cast<char*>(pattern) + strlen(pattern);

		for (auto Current = Start; Current < End; ++Current)
		{
			if (*Current == '?')
			{
				++Current;
				if (*Current == '?') ++Current;
				Bytes.push_back(-1);
			}
			else { Bytes.push_back(strtoul(Current, &Current, 16)); }
		}
		return Bytes;
	};

	return FindPatternInRange(patternToByte(Signature), Start, Range, bRelative, Offset);
}

inline void* FindPattern(const char* Signature, uint32_t Offset = 0, bool bSearchAllSections = false, uintptr_t StartAddress = 0x0)
{
	//std::cout << "StartAddr: " << StartAddress << "\n";

	const auto [ImageBase, ImageSize] = GetImageBaseAndSize();

	uintptr_t SearchStart = ImageBase;
	uintptr_t SearchRange = ImageSize;

	if (!bSearchAllSections)
	{
		const auto [TextSection, TextSize] = GetSectionByName(ImageBase, ".text");

		if (TextSection != 0x0 && TextSize != 0x0)
		{
			SearchStart = TextSection;
			SearchRange = TextSize;
		}
		else
		{
			bSearchAllSections = true;
		}
	}

	const uintptr_t SearchEnd = ImageBase + SearchRange;

	/* If the StartAddress is not default nullptr, and is out of memory-range */
	if (StartAddress != 0x0 && (StartAddress < SearchStart || StartAddress >= SearchEnd))
		return nullptr;

	/* Add a byte to the StartAddress to prevent instantly returning the previous result */
	SearchStart = StartAddress != 0x0 ? (StartAddress + 0x1) : ImageBase;
	SearchRange = StartAddress != 0x0 ? SearchEnd - StartAddress : ImageSize;

	return FindPatternInRange(Signature, reinterpret_cast<uint8_t*>(SearchStart), SearchRange, Offset != 0x0, Offset);
}


template<typename T>
inline T* FindAlignedValueInProcessInRange(T Value, int32_t Alignment, uintptr_t StartAddress, uint32_t Range)
{
	constexpr int32_t ElementSize = sizeof(T);

	for (uint32_t i = 0x0; i < Range; i += Alignment)
	{
		T* TypedPtr = reinterpret_cast<T*>(StartAddress + i);

		if (*TypedPtr == Value)
			return TypedPtr;
	}

	return nullptr;
}

template<typename T>
inline T* FindAlignedValueInProcess(T Value, const std::string& Sectionname = ".data", int32_t Alignment = alignof(T), bool bSearchAllSections = false)
{
	const auto [ImageBase, ImageSize] = GetImageBaseAndSize();

	uintptr_t SearchStart = ImageBase;
	uintptr_t SearchRange = ImageSize;

	if (!bSearchAllSections)
	{
		const auto [SectionStart, SectionSize] = GetSectionByName(ImageBase, Sectionname);

		if (SectionStart != 0x0 && SectionSize != 0x0)
		{
			SearchStart = SectionStart;
			SearchRange = SectionSize;
		}
		else
		{
			bSearchAllSections = true;
		}
	}

	T* Result = FindAlignedValueInProcessInRange(Value, Alignment, SearchStart, SearchRange);

	if (!Result && SearchStart != ImageBase)
		return FindAlignedValueInProcess(Value, Sectionname, Alignment, true);

	return Result;
}

template<bool bShouldResolve32BitJumps = true>
inline std::pair<const void*, int32_t> IterateVTableFunctions(void** VTable, const std::function<bool(const uint8_t* Addr, int32_t Index)>& CallBackForEachFunc, int32_t NumFunctions = 0x150, int32_t OffsetFromStart = 0x0)
{
	[[maybe_unused]] auto Resolve32BitRelativeJump = [](const void* FunctionPtr) -> const uint8_t*
	{
		if constexpr (bShouldResolve32BitJumps)
		{
			const uint8_t* Address = reinterpret_cast<const uint8_t*>(FunctionPtr);
			if (*Address == 0xE9)
			{
				const uint8_t* Ret = ((Address + 5) + *reinterpret_cast<const int32_t*>(Address + 1));

				if (IsInProcessRange(Ret))
					return Ret;
			}
		}

		return reinterpret_cast<const uint8_t*>(FunctionPtr);
	};


	if (!CallBackForEachFunc)
		return { nullptr, -1 };

	for (int i = 0; i < 0x150; i++)
	{
		const uintptr_t CurrentFuncAddress = reinterpret_cast<uintptr_t>(VTable[i]);

		if (CurrentFuncAddress == NULL || !IsInProcessRange(CurrentFuncAddress))
			break;

		const uint8_t* ResolvedAddress = Resolve32BitRelativeJump(reinterpret_cast<const uint8_t*>(CurrentFuncAddress));

		if (CallBackForEachFunc(ResolvedAddress, i))
			return { ResolvedAddress, i };
	}

	return { nullptr, -1 };
}

struct MemAddress
{
public:
	uintptr_t Address;

private:
	//pasted
	static std::vector<int32_t> PatternToBytes(const char* pattern)
	{
		auto bytes = std::vector<int>{};
		const auto start = const_cast<char*>(pattern);
		const auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current)
		{
			if (*current == '?')
			{
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(-1);
			}
			else { bytes.push_back(strtoul(current, &current, 16)); }
		}
		return bytes;
	}

	/* Function to determine whether this position is a function-return. Only "ret" instructions with pop operations before them and without immediate values are considered. */
	static bool IsFunctionRet(const uint8_t* Address)
	{
		if (!Address || (Address[0] != 0xC3 && Address[0] != 0xCB))
			return false;

		/* Opcodes representing pop instructions for x64 registers. Pop operations for r8-r15 are prefixed with 0x41. */
		const uint8_t AsmBytePopOpcodes[] = { 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F };

		const uint8_t ByteOneBeforeRet = Address[-1];
		const uint8_t ByteTwoBeforeRet = Address[-2];

		for (const uint8_t AsmPopByte : AsmBytePopOpcodes)
		{
			if (ByteOneBeforeRet == AsmPopByte)
				return true;
		}

		return false;
	}

public:
	inline MemAddress(std::nullptr_t)
		: Address(NULL)
	{
	}
	inline MemAddress(void* Addr)
		: Address(reinterpret_cast<uintptr_t>(Addr))
	{
	}
	inline MemAddress(uintptr_t Addr)
		: Address(Addr)
	{
	}

	explicit operator bool()
	{
		return Address != NULL;
	}

	template<typename T>
	explicit operator T*()
	{
		return reinterpret_cast<T*>(Address);
	}
	operator uintptr_t()
	{
		return Address;
	}

	inline bool operator==(MemAddress Other) const
	{
		return Address == Other.Address;
	}

	inline MemAddress operator+(int Value) const
	{
		return Address + Value;
	}

	inline MemAddress operator-(int Value) const
	{
		return Address - Value;
	}

	template<typename T = void>
	inline T* Get()
	{
		return reinterpret_cast<T*>(Address);
	}

	template<typename T = void>
	inline const T* Get() const
	{
		return reinterpret_cast<const T*>(Address);
	}

	/* 
	* Checks if the current address is a valid 32-bit relative 'jmp' instruction. and returns the address if true. 
	* 
	* If true: Returns resolved jump-target.
	* If false: Returns current address.
	*/
	inline MemAddress ResolveJumpIfInstructionIsJump(MemAddress DefaultReturnValueOnFail = nullptr) const
	{
		if (!ASMUtils::Is32BitRIPRelativeJump(Address))
			return DefaultReturnValueOnFail;

		const uintptr_t TargetAddress = ASMUtils::Resolve32BitRIPRelativeJumpTarget(Address);

		if (!IsInProcessRange(TargetAddress))
			return DefaultReturnValueOnFail;

		return TargetAddress;
	}

	/* Helper to find the end of a function based on 'pop' instructions followed by 'ret' */
	inline MemAddress FindFunctionEnd(uint32_t Range = 0xFFFF) const
	{
		if (!Address)
			return nullptr;

		if (Range > 0xFFFF)
			Range = 0xFFFF;

		for (int i = 0; i < Range; i++)
		{
			if (IsFunctionRet(Get<uint8_t>() + i))
				return Address + i;
		}

		return  nullptr;
	}

	/* Helper function to find a Pattern in a Range relative to the current position */
	inline MemAddress RelativePattern(const char* Pattern, int32_t Range, int32_t Relative = 0) const
	{
		if (!Address)
			return nullptr;

		return FindPatternInRange(Pattern, Get<uint8_t>(), Range, Relative != 0, Relative);
	}

	/*
	* A Function to find calls relative to the instruction pointer (RIP). Other calls are ignored.
	* 
	* Disclaimers:
	*	Negative index to search up, positive index to search down. 
	*	Function considers all E8 bytes as 'call' instructsion, that would make for a valid call (to address within process-bounds).
	* 
	* OneBasedFuncIndex -> Index of a function we want to find, n-th sub_ in IDA starting from this MemAddress
	* IsWantedTarget -> Allows for the caller to pass a callback to verify, that the function at index n is the target we're looking for; else continue searching for a valid target.
	*/
	inline MemAddress GetRipRelativeCalledFunction(int32_t OneBasedFuncIndex, bool(*IsWantedTarget)(MemAddress CalledAddr) = nullptr) const
	{
		if (!Address || OneBasedFuncIndex == 0)
			return nullptr;

		const int32_t Multiply = OneBasedFuncIndex > 0 ? 1 : -1;

		/* Returns Index if FunctionIndex is positive, else -1 if the index is less than 0 */
		auto GetIndex = [=](int32_t Index) -> int32_t { return Index * Multiply; };

		constexpr int32_t RealtiveCallOpcodeCount = 0x5;

		int32_t NumCalls = 0;

		for (int i = 0; i < 0xFFF; i++)
		{
			const int32_t Index = GetIndex(i);

			/* If this isn't a call, we don't care about it and want to continue */
			if (Get<uint8_t>()[Index] != 0xE8)
				continue;

			const int32_t RelativeOffset = *reinterpret_cast<int32_t*>(Address + Index + 0x1 /* 0xE8 byte */);
			MemAddress RelativeCallTarget = Address + Index + RelativeOffset + RealtiveCallOpcodeCount;

			if (!IsInProcessRange(RelativeCallTarget))
				continue;

			if (++NumCalls == abs(OneBasedFuncIndex))
			{
				/* This is not the target we wanted, even tho it's at the right index. Decrement the index to the value before and check if the next call satisfies the custom-condition. */
				if (IsWantedTarget && !IsWantedTarget(RelativeCallTarget))
				{
					--NumCalls;
					continue;
				}

				return RelativeCallTarget;
			}
		}

		return nullptr;
	}

	/* Note: Unrealiable */
	inline MemAddress FindNextFunctionStart() const
	{
		if (!Address)
			return MemAddress(nullptr);

		uintptr_t FuncEnd = (uintptr_t)FindFunctionEnd();

		return FuncEnd % 0x10 != 0 ? FuncEnd + (0x10 - (FuncEnd % 0x10)) : FuncEnd;
	}
};

template<typename Type = const char*>
inline MemAddress FindByString(Type RefStr)
{
	const auto [ImageBase, ImageSize] = GetImageBaseAndSize();

	uintptr_t SearchStart = ImageBase;
	uintptr_t SearchRange = ImageSize;

	const auto [RDataSection, RDataSize] = GetSectionByName(ImageBase, ".rdata");
	const auto [TextSection, TextSize] = GetSectionByName(ImageBase, ".text");
	
	if (!RDataSection || !TextSection)
		return nullptr;

	uintptr_t StringAddress = NULL;

	const auto RetfStrLength = StrlenHelper(RefStr);

	for (int i = 0; i < RDataSize; i++)
	{
		if (StrnCmpHelper(RefStr, reinterpret_cast<Type>(RDataSection + i), RetfStrLength) == 0)
		{
			StringAddress = RDataSection + i;
			break;
		}
	}

	if (!StringAddress)
		return nullptr;

	for (int i = 0; i < TextSize; i++)
	{
		// opcode: lea
		const uint8_t CurrentByte = *reinterpret_cast<const uint8_t*>(TextSection + i);
		const uint8_t NextByte    = *reinterpret_cast<const uint8_t*>(TextSection + i + 0x1);

		if ((CurrentByte == 0x4C || CurrentByte == 0x48) && NextByte == 0x8D)
		{
			const uintptr_t StrPtr = ASMUtils::Resolve32BitRelativeLea(TextSection + i);

			if (StrPtr == StringAddress)
				return { TextSection + i };
		}
	}

	return nullptr;
}

inline MemAddress FindByWString(const wchar_t* RefStr)
{
	return FindByString<const wchar_t*>(RefStr);
}

/* Slower than FindByString */
template<bool bCheckIfLeaIsStrPtr = false, typename CharType = char>
inline MemAddress FindByStringInAllSections(const CharType* RefStr, uintptr_t StartAddress = 0x0, int32_t Range = 0x0)
{
	static_assert(std::is_same_v<CharType, char> || std::is_same_v<CharType, wchar_t>, "FindByStringInAllSections only supports 'char' and 'wchar_t', but was called with other type.");

	/* Stop scanning when arriving 0x10 bytes before the end of the memory range */
	constexpr int32_t OffsetFromMemoryEnd = 0x10;

	const auto [ImageBase, ImageSize] = GetImageBaseAndSize();

	const uintptr_t ImageEnd = ImageBase + ImageSize;

	/* If the StartAddress is not default nullptr, and is out of memory-range */
	if (StartAddress != 0x0 && (StartAddress < ImageBase || StartAddress > ImageEnd))
		return nullptr;

	/* Add a few bytes to the StartAddress to prevent instantly returning the previous result */
	uint8_t* SearchStart = StartAddress ? (reinterpret_cast<uint8_t*>(StartAddress) + 0x5) : reinterpret_cast<uint8_t*>(ImageBase);
	DWORD SearchRange = StartAddress ? ImageEnd - StartAddress : ImageSize;

	if (Range != 0x0)
		SearchRange = min(Range, SearchRange);

	if ((StartAddress + SearchRange) >= ImageEnd)
		SearchRange -= OffsetFromMemoryEnd;

	const int32_t RefStrLen = StrlenHelper(RefStr);

	for (uintptr_t i = 0; i < SearchRange; i++)
	{
		// opcode: lea
		if ((SearchStart[i] == uint8_t(0x4C) || SearchStart[i] == uint8_t(0x48)) && SearchStart[i + 1] == uint8_t(0x8D))
		{
			const uintptr_t StrPtr = ASMUtils::Resolve32BitRelativeLea(reinterpret_cast<uintptr_t>(SearchStart + i));

			if (!IsInProcessRange(StrPtr))
				continue;

			if (StrnCmpHelper(RefStr, reinterpret_cast<const CharType*>(StrPtr), RefStrLen))
				return { SearchStart + i };

			if constexpr (bCheckIfLeaIsStrPtr)
			{
				const CharType* StrPtrContentFirst8Bytes = *reinterpret_cast<const CharType* const*>(StrPtr);

				if (!IsInProcessRange(StrPtrContentFirst8Bytes))
					continue;

				if (StrnCmpHelper(RefStr, StrPtrContentFirst8Bytes, RefStrLen))
					return { SearchStart + i };
			}
		}
	}

	return nullptr;
}

template<typename Type = const char*>
inline MemAddress FindUnrealExecFunctionByString(Type RefStr, void* StartAddress = nullptr)
{
	const auto [ImageBase, ImageSize] = GetImageBaseAndSize();

	uint8_t* SearchStart = StartAddress ? reinterpret_cast<uint8_t*>(StartAddress) : reinterpret_cast<uint8_t*>(ImageBase);
	DWORD SearchRange = ImageSize;

	const int32_t RefStrLen = StrlenHelper(RefStr);

	static auto IsValidExecFunctionNotSetupFunc = [](uintptr_t Address) -> bool
	{
		/* 
		* UFuntion construction functions setting up exec functions always start with these asm instructions:
		* sub rsp, 28h
		* 
		* In opcode bytes: 48 83 EC 28
		*/
		if (*reinterpret_cast<int32_t*>(Address) == 0x284883EC || *reinterpret_cast<int32_t*>(Address) == 0x4883EC28)
			return false;

		MemAddress AsAddress(Address);

		/* A signature specifically made for UFunctions-construction functions. If this signature is found we're in a function that we *don't* want. */
		if (AsAddress.RelativePattern("48 8B 05 ? ? ? ? 48 85 C0 75 ? 48 8D 15", 0x28) != nullptr)
			return false;

		return true;
	};

	for (uintptr_t i = 0; i < (SearchRange - 0x8); i += sizeof(void*))
	{
		const uintptr_t PossibleStringAddress = *reinterpret_cast<uintptr_t*>(SearchStart + i);
		const uintptr_t PossibleExecFuncAddress = *reinterpret_cast<uintptr_t*>(SearchStart + i + sizeof(void*));

		if (PossibleStringAddress == PossibleExecFuncAddress)
			continue;

		if (!IsInProcessRange(PossibleStringAddress) || !IsInProcessRange(PossibleExecFuncAddress))
			continue;

		if constexpr (std::is_same<Type, const char*>())
		{
			if (strncmp(reinterpret_cast<const char*>(RefStr), reinterpret_cast<const char*>(PossibleStringAddress), RefStrLen) == 0 && IsValidExecFunctionNotSetupFunc(PossibleExecFuncAddress))
			{
				// std::cout << "FoundStr ref: " << reinterpret_cast<const char*>(PossibleStringAddress) << "\n";

				return { PossibleExecFuncAddress };
			}
		}
		else
		{
			if (wcsncmp(reinterpret_cast<const wchar_t*>(RefStr), reinterpret_cast<const wchar_t*>(PossibleStringAddress), RefStrLen) == 0 && IsValidExecFunctionNotSetupFunc(PossibleExecFuncAddress))
			{
				// std::wcout << L"FoundStr wref: " << reinterpret_cast<const wchar_t*>(PossibleStringAddress) << L"\n";

				return { PossibleExecFuncAddress };
			}
		}
	}

	return nullptr;
}



/* Slower than FindByWString */
template<bool bCheckIfLeaIsStrPtr = false>
inline MemAddress FindByWStringInAllSections(const wchar_t* RefStr)
{
	return FindByStringInAllSections<bCheckIfLeaIsStrPtr, wchar_t>(RefStr);
}


namespace FileNameHelper
{
	inline void MakeValidFileName(std::string& InOutName)
	{
		for (char& c : InOutName)
		{
			if (c == '<' || c == '>' || c == ':' || c == '\"' || c == '/' || c == '\\' || c == '|' || c == '?' || c == '*')
				c = '_';
		}
	}
}


/*pasted memcury*/

/*
   Memcury is a single-header file library for memory manipulation in C++.

   Containers:
       -PE::Address: A pointer container.
       -PE::Section: Portable executable section container for internal usage.

   Modules:
       -Scanner:
           -Constructors:
               -Default: Takes a pointer to start the scanning from.
               -FindPattern: Finds a pattern in memory.
               -FindStringRef: Finds a string reference in memory, supports all types of strings.
           -Functions:
               -SetTargetModule: Sets the target module for the scanner.
               -ScanFor: Scans for a byte(s) near the current address.
               -FindFunctionBoundary: Finds the boundary of a function near the current address.
               -RelativeOffset: Gets the relative offset of the current address.
               -AbsoluteOffset: Gets the absolute offset of the current address.
               -GetAs: Gets the current address as a type.
               -Get: Gets the current address as an int64.

       -TrampolineHook:
           -Constructors:
               -Default: Takes a pointer pointer to the target function and a pointer to the hook function.
           -Functions:
               -Commit: Commits the hook.
               -Revert: Reverts the hook.
               -Toggle: Toggles the hook on\off.

       -VEHHook:
           -Functions:
               -Init: Initializes the VEH Hook system.
               -AddHook: Adds a hook to the VEH Hook system.
               -RemoveHook: Removes a hook from the VEH Hook system.
*/

#include <string>
#include <format>
#include <vector>
#include <stdexcept>
#include <type_traits>
#include <intrin.h>
#include <Windows.h>
#include <source_location>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

#define MemcuryAssert(cond)                                              \
    if (!(cond))                                                         \
    {                                                                    \
        MessageBoxA(nullptr, #cond, __FUNCTION__, MB_ICONERROR | MB_OK); \
        Memcury::Safety::FreezeCurrentThread();                          \
    }

#define MemcuryAssertM(cond, msg)                                      \
    if (!(cond))                                                       \
    {                                                                  \
        MessageBoxA(nullptr, msg, __FUNCTION__, MB_ICONERROR | MB_OK); \
        Memcury::Safety::FreezeCurrentThread();                        \
    }

#define MemcuryThrow(msg)                                          \
    MessageBoxA(nullptr, msg, __FUNCTION__, MB_ICONERROR | MB_OK); \
    Memcury::Safety::FreezeCurrentThread();

namespace Memcury
{
    extern "C" IMAGE_DOS_HEADER __ImageBase;

    inline auto GetCurrentModule() -> HMODULE
    {
        return reinterpret_cast<HMODULE>(&__ImageBase);
    }

    namespace Util
    {
        template <typename T>
        constexpr static auto IsInRange(T value, T min, T max) -> bool
        {
            return value >= min && value < max;
        }

        constexpr auto StrHash(const char* str, int h = 0) -> unsigned int
        {
            return !str[h] ? 5381 : (StrHash(str, h + 1) * 33) ^ str[h];
        }

        inline auto IsSamePage(void* A, void* B) -> bool
        {
            MEMORY_BASIC_INFORMATION InfoA;
            if (!VirtualQuery(A, &InfoA, sizeof(InfoA)))
            {
                return true;
            }

            MEMORY_BASIC_INFORMATION InfoB;
            if (!VirtualQuery(B, &InfoB, sizeof(InfoB)))
            {
                return true;
            }

            return InfoA.BaseAddress == InfoB.BaseAddress;
        }

        inline auto GetModuleStartAndEnd() -> std::pair<uintptr_t, uintptr_t>
        {
            auto HModule = GetCurrentModule();
            auto NTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((uintptr_t)HModule + reinterpret_cast<PIMAGE_DOS_HEADER>((uintptr_t)HModule)->e_lfanew);

            uintptr_t dllStart = (uintptr_t)HModule;
            uintptr_t dllEnd = (uintptr_t)HModule + NTHeaders->OptionalHeader.SizeOfImage;

            return { dllStart, dllEnd };
        }

        inline auto CopyToClipboard(std::string str)
        {
            auto mem = GlobalAlloc(GMEM_FIXED, str.size() + 1);
            memcpy(mem, str.c_str(), str.size() + 1);

            OpenClipboard(nullptr);
            EmptyClipboard();
            SetClipboardData(CF_TEXT, mem);
            CloseClipboard();

            GlobalFree(mem);
        }
    }

    namespace Safety
    {
        enum class ExceptionMode
        {
            None,
            CatchDllExceptionsOnly,
            CatchAllExceptions
        };

        static auto FreezeCurrentThread() -> void
        {
            SuspendThread(GetCurrentThread());
        }

        static auto PrintStack(CONTEXT* ctx) -> void
        {
            STACKFRAME64 stack;
            memset(&stack, 0, sizeof(STACKFRAME64));

            auto process = GetCurrentProcess();
            auto thread = GetCurrentThread();

            SymInitialize(process, NULL, TRUE);

            bool result;
            DWORD64 displacement = 0;

            char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)]{ 0 };
            char name[256]{ 0 };
            char module[256]{ 0 };

            PSYMBOL_INFO symbolInfo = (PSYMBOL_INFO)buffer;

            for (ULONG frame = 0;; frame++)
            {
                result = StackWalk64(
                    IMAGE_FILE_MACHINE_AMD64,
                    process,
                    thread,
                    &stack,
                    ctx,
                    NULL,
                    SymFunctionTableAccess64,
                    SymGetModuleBase64,
                    NULL);

                if (!result)
                    break;

                symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
                symbolInfo->MaxNameLen = MAX_SYM_NAME;
                SymFromAddr(process, (ULONG64)stack.AddrPC.Offset, &displacement, symbolInfo);

                HMODULE hModule = NULL;
                lstrcpyA(module, "");
                GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (const wchar_t*)(stack.AddrPC.Offset), &hModule);

                if (hModule != NULL)
                    GetModuleFileNameA(hModule, module, 256);

                printf("[%lu] Name: %s - Address: %p  - Module: %s\n", frame, symbolInfo->Name, (void*)symbolInfo->Address, module);
            }
        }

        template <ExceptionMode mode>
        auto MemcuryGlobalHandler(EXCEPTION_POINTERS* ExceptionInfo) -> long
        {
            auto [dllStart, dllEnd] = Util::GetModuleStartAndEnd();

            if constexpr (mode == ExceptionMode::CatchDllExceptionsOnly)
            {
                if (!Util::IsInRange(ExceptionInfo->ContextRecord->Rip, dllStart, dllEnd))
                {
                    return EXCEPTION_CONTINUE_SEARCH;
                }
            }

            auto message = std::format("Memcury caught an exception at [{:x}]\nPress Yes if you want the address to be copied to your clipboard", ExceptionInfo->ContextRecord->Rip);
            if (MessageBoxA(nullptr, message.c_str(), "Error", MB_ICONERROR | MB_YESNO) == IDYES)
            {
                std::string clip = std::format("{:x}", ExceptionInfo->ContextRecord->Rip);
                Util::CopyToClipboard(clip);
            }

            PrintStack(ExceptionInfo->ContextRecord);

            FreezeCurrentThread();

            return EXCEPTION_EXECUTE_HANDLER;
        }

        template <ExceptionMode mode>
        static auto SetExceptionMode() -> void
        {
            SetUnhandledExceptionFilter(MemcuryGlobalHandler<mode>);
        }
    }

    namespace Globals
    {
        constexpr const bool bLogging = true;

        inline const char* moduleName = nullptr;
    }

    namespace ASM
    {
        //@todo: this whole namespace needs a rework, should somehow make this more modern and less ugly.
        enum MNEMONIC : uint8_t
        {
            JMP_REL8 = 0xEB,
            JMP_REL32 = 0xE9,
            JMP_EAX = 0xE0,
            CALL = 0xE8,
            LEA = 0x8D,
            CDQ = 0x99,
            CMOVL = 0x4C,
            CMOVS = 0x48,
            CMOVNS = 0x49,
            NOP = 0x90,
            INT3 = 0xCC,
            RETN_REL8 = 0xC2,
            RETN = 0xC3,
            NONE = 0x00
        };

        constexpr int SIZE_OF_JMP_RELATIVE_INSTRUCTION = 5;
        constexpr int SIZE_OF_JMP_ABSLOUTE_INSTRUCTION = 13;

        constexpr auto MnemonicToString(MNEMONIC e) -> const char*
        {
            switch (e)
            {
            case JMP_REL8:
                return "JMP_REL8";
            case JMP_REL32:
                return "JMP_REL32";
            case JMP_EAX:
                return "JMP_EAX";
            case CALL:
                return "CALL";
            case LEA:
                return "LEA";
            case CDQ:
                return "CDQ";
            case CMOVL:
                return "CMOVL";
            case CMOVS:
                return "CMOVS";
            case CMOVNS:
                return "CMOVNS";
            case NOP:
                return "NOP";
            case INT3:
                return "INT3";
            case RETN_REL8:
                return "RETN_REL8";
            case RETN:
                return "RETN";
            case NONE:
                return "NONE";
            default:
                return "UNKNOWN";
            }
        }

        constexpr auto Mnemonic(const char* s) -> MNEMONIC
        {
            switch (Util::StrHash(s))
            {
            case Util::StrHash("JMP_REL8"):
                return JMP_REL8;
            case Util::StrHash("JMP_REL32"):
                return JMP_REL32;
            case Util::StrHash("JMP_EAX"):
                return JMP_EAX;
            case Util::StrHash("CALL"):
                return CALL;
            case Util::StrHash("LEA"):
                return LEA;
            case Util::StrHash("CDQ"):
                return CDQ;
            case Util::StrHash("CMOVL"):
                return CMOVL;
            case Util::StrHash("CMOVS"):
                return CMOVS;
            case Util::StrHash("CMOVNS"):
                return CMOVNS;
            case Util::StrHash("NOP"):
                return NOP;
            case Util::StrHash("INT3"):
                return INT3;
            case Util::StrHash("RETN_REL8"):
                return RETN_REL8;
            case Util::StrHash("RETN"):
                return RETN;
            default:
                return NONE;
            }
        }

        inline auto byteIsA(uint8_t byte, MNEMONIC opcode) -> bool
        {
            return byte == opcode;
        }

        inline auto byteIsAscii(uint8_t byte) -> bool
        {
            static constexpr bool isAscii[0x100] = {
                false, false, false, false, false, false, false, false, false, true, true, false, false, true, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false,
                false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false
            };

            return isAscii[byte];
        }

        inline bool isJump(uint8_t byte)
        {
            return byte >= 0x70 && byte <= 0x7F;
        }

        static auto pattern2bytes(const char* pattern) -> std::vector<int>
        {
            auto bytes = std::vector<int>{};
            const auto start = const_cast<char*>(pattern);
            const auto end = const_cast<char*>(pattern) + strlen(pattern);

            for (auto current = start; current < end; ++current)
            {
                if (*current == '?')
                {
                    ++current;
                    if (*current == '?')
                        ++current;
                    bytes.push_back(-1);
                }
                else
                {
                    bytes.push_back(strtoul(current, &current, 16));
                }
            }
            return bytes;
        }
    }

    namespace PE
    {
        inline auto SetCurrentModule(const char* moduleName) -> void
        {
            Globals::moduleName = moduleName;
        }

        inline auto GetModuleBase() -> uintptr_t
        {
            return reinterpret_cast<uintptr_t>(GetModuleHandleA(Globals::moduleName));
        }

        inline auto GetDOSHeader() -> PIMAGE_DOS_HEADER
        {
            return reinterpret_cast<PIMAGE_DOS_HEADER>(GetModuleBase());
        }

        inline auto GetNTHeaders() -> PIMAGE_NT_HEADERS
        {
            return reinterpret_cast<PIMAGE_NT_HEADERS>(GetModuleBase() + GetDOSHeader()->e_lfanew);
        }

        class Address
        {
            uintptr_t _address;

        public:
            Address()
            {
                _address = 0;
            }

            Address(uintptr_t address)
                : _address(address)
            {
            }

            Address(void* address)
                : _address(reinterpret_cast<uintptr_t>(address))
            {
            }

            auto operator=(uintptr_t address) -> Address
            {
                _address = address;
                return *this;
            }

            auto operator=(void* address) -> Address
            {
                _address = reinterpret_cast<uintptr_t>(address);
                return *this;
            }

            auto operator+(uintptr_t offset) -> Address
            {
                return Address(_address + offset);
            }

            bool operator>(uintptr_t offset)
            {
                return _address > offset;
            }

            bool operator>(Address address)
            {
                return _address > address._address;
            }

            bool operator<(uintptr_t offset)
            {
                return _address < offset;
            }

            bool operator<(Address address)
            {
                return _address < address._address;
            }

            bool operator>=(uintptr_t offset)
            {
                return _address >= offset;
            }

            bool operator>=(Address address)
            {
                return _address >= address._address;
            }

            bool operator<=(uintptr_t offset)
            {
                return _address <= offset;
            }

            bool operator<=(Address address)
            {
                return _address <= address._address;
            }

            bool operator==(uintptr_t offset)
            {
                return _address == offset;
            }

            bool operator==(Address address)
            {
                return _address == address._address;
            }

            bool operator!=(uintptr_t offset)
            {
                return _address != offset;
            }

            bool operator!=(Address address)
            {
                return _address != address._address;
            }

            auto RelativeOffset(uint32_t offset) -> Address
            {
                _address = ((_address + offset + 4) + *(int32_t*)(_address + offset));
                return *this;
            }

            /* used to get the address of a non direct pointer ex: [rbx + 50] */
            auto AbsoluteOffset(uint32_t offset) -> Address
            {
                _address = _address + offset;
                return *this;
            }

            auto Jump() -> Address
            {
                if (ASM::isJump(*reinterpret_cast<UINT8*>(_address)))
                {
                    UINT8 toSkip = *reinterpret_cast<UINT8*>(_address + 1);
                    _address = _address + 2 + toSkip;
                }

                return *this;
            }

            auto Get() -> uintptr_t
            {
                return _address;
            }

            template <typename T>
            auto GetAs() -> T
            {
                return reinterpret_cast<T>(_address);
            }

            auto IsValid() -> bool
            {
                return _address != 0;
            }
        };

        class Section
        {
        public:
            std::string sectionName;
            IMAGE_SECTION_HEADER rawSection;

            static auto GetAllSections() -> std::vector<Section>
            {
                std::vector<Section> sections;

                auto sectionsSize = GetNTHeaders()->FileHeader.NumberOfSections;
                auto section = IMAGE_FIRST_SECTION(GetNTHeaders());

                for (WORD i = 0; i < sectionsSize; i++, section++)
                {
                    auto secName = std::string((char*)section->Name);

                    sections.push_back({ secName, *section });
                }

                return sections;
            }

            static auto GetSection(std::string sectionName) -> Section
            {
                for (auto& section : GetAllSections())
                {
                    if (section.sectionName == sectionName)
                    {
                        return section;
                    }
                }

                MemcuryThrow("Section not found");
                return Section{};
            }

            auto GetSectionSize() -> uint32_t
            {
                return rawSection.Misc.VirtualSize;
            }

            auto GetSectionStart() -> Address
            {
                return Address(GetModuleBase() + rawSection.VirtualAddress);
            }

            auto GetSectionEnd() -> Address
            {
                return Address(GetSectionStart() + GetSectionSize());
            }

            auto isInSection(Address address) -> bool
            {
                return address >= GetSectionStart() && address < GetSectionEnd();
            }
        };
    }

    class Scanner
    {
        PE::Address _address;

    public:
        Scanner(PE::Address address)
            : _address(address)
        {
        }

        static auto SetTargetModule(const char* moduleName) -> void
        {
            PE::SetCurrentModule(moduleName);
        }

        static auto FindPatternEx(HANDLE handle, const char* pattern, const char* mask, uint64_t begin, uint64_t end) -> Scanner
        {
            auto scan = [](const char* pattern, const char* mask, char* begin, unsigned int size) -> char*
                {
                    size_t patternLen = strlen(mask);
                    for (unsigned int i = 0; i < size - patternLen; i++)
                    {
                        bool found = true;
                        for (unsigned int j = 0; j < patternLen; j++)
                        {
                            if (mask[j] != '?' && pattern[j] != *(begin + i + j))
                            {
                                found = false;
                                break;
                            }
                        }

                        if (found)
                            return (begin + i);
                    }
                    return nullptr;
                };

            uint64_t match = NULL;
            SIZE_T bytesRead;
            char* buffer = nullptr;
            MEMORY_BASIC_INFORMATION mbi = { 0 };

            uint64_t curr = begin;

            for (uint64_t curr = begin; curr < end; curr += mbi.RegionSize)
            {
                if (!VirtualQueryEx(handle, (void*)curr, &mbi, sizeof(mbi)))
                    continue;

                if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS)
                    continue;

                buffer = new char[mbi.RegionSize];

                if (ReadProcessMemory(handle, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead))
                {
                    char* internalAddr = scan(pattern, mask, buffer, (unsigned int)bytesRead);

                    if (internalAddr != nullptr)
                    {
                        match = curr + (uint64_t)(internalAddr - buffer);
                        break;
                    }
                }
            }
            delete[] buffer;

            MemcuryAssertM(match != 0, "FindPatternEx return nullptr");

            return Scanner(match);
        }

        static auto FindPatternEx(HANDLE handle, const char* sig) -> Scanner
        {
            char pattern[100];
            char mask[100];

            char lastChar = ' ';
            unsigned int j = 0;

            for (unsigned int i = 0; i < strlen(sig); i++)
            {
                if ((sig[i] == '?' || sig[i] == '*') && (lastChar != '?' && lastChar != '*'))
                {
                    pattern[j] = mask[j] = '?';
                    j++;
                }

                else if (isspace(lastChar))
                {
                    pattern[j] = lastChar = (char)strtol(&sig[i], 0, 16);
                    mask[j] = 'x';
                    j++;
                }
                lastChar = sig[i];
            }
            pattern[j] = mask[j] = '\0';

            auto module = (uint64_t)GetModuleHandle(nullptr);

            return FindPatternEx(handle, pattern, mask, module, module + Memcury::PE::GetNTHeaders()->OptionalHeader.SizeOfImage);
        }

        static auto FindPattern(const char* signature, bool bShouldWarn = false) -> Scanner
        {
            PE::Address add{ nullptr };

            const auto sizeOfImage = PE::GetNTHeaders()->OptionalHeader.SizeOfImage;
            auto patternBytes = ASM::pattern2bytes(signature);
            const auto scanBytes = reinterpret_cast<std::uint8_t*>(PE::GetModuleBase());

            const auto s = patternBytes.size();
            const auto d = patternBytes.data();

            for (auto i = 0ul; i < sizeOfImage - s; ++i)
            {
                bool found = true;
                for (auto j = 0ul; j < s; ++j)
                {
                    if (scanBytes[i + j] != d[j] && d[j] != -1)
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    add = reinterpret_cast<uintptr_t>(&scanBytes[i]);
                    break;
                }
            }

            if (bShouldWarn)
            {
                MemcuryAssertM(add != 0, (std::string("FindPattern failed for signaure: ") + signature).c_str());
            }

            return Scanner(add);
        }

        // Supports wide and normal strings both std and pointers
        template <typename T = const wchar_t*>
        static auto FindStringRef(T string, bool bShouldWarn = false, bool find_first = false) -> Scanner
        {
            PE::Address add{ nullptr };

            constexpr auto bIsWide = std::is_same<T, const wchar_t*>::value;
            constexpr auto bIsChar = std::is_same<T, const char*>::value;

            constexpr auto bIsPtr = bIsWide || bIsChar;

            auto textSection = PE::Section::GetSection(".text");
            auto rdataSection = PE::Section::GetSection(".rdata");

            const auto scanBytes = reinterpret_cast<std::uint8_t*>(textSection.GetSectionStart().Get());

            // scan only text section
            for (DWORD i = 0x0; i < textSection.GetSectionSize(); i++)
            {
                if ((scanBytes[i] == ASM::CMOVL || scanBytes[i] == ASM::CMOVS) && scanBytes[i + 1] == ASM::LEA)
                {
                    auto stringAdd = PE::Address(&scanBytes[i]).RelativeOffset(3);

                    // Check if the string is in the .rdata section
                    if (rdataSection.isInSection(stringAdd))
                    {
                        auto strBytes = stringAdd.GetAs<std::uint8_t*>();

                        // Check if the first char is printable
                        if (ASM::byteIsAscii(strBytes[0]))
                        {
                            if constexpr (!bIsPtr)
                            {
                                typedef T::value_type char_type;

                                auto lea = stringAdd.GetAs<char_type*>();

                                T leaT(lea);

                                if (leaT == string)
                                {
                                    add = PE::Address(&scanBytes[i]);
                                    if (find_first)
                                        break;
                                }
                            }
                            else
                            {
                                auto lea = stringAdd.GetAs<T>();

                                if constexpr (bIsWide)
                                {
                                    if (wcscmp(string, lea) == 0)
                                    {
                                        add = PE::Address(&scanBytes[i]);
                                        if (find_first)
                                            break;
                                    }
                                }
                                else
                                {
                                    if (strcmp(string, lea) == 0)
                                    {
                                        add = PE::Address(&scanBytes[i]);
                                        if (find_first)
                                            break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (bShouldWarn)
            {
                MemcuryAssertM(add != 0, "Failed to find string");
            }

            return Scanner(add);
        }

        auto Jump() -> Scanner
        {
            _address.Jump();
            return *this;
        }

        auto ScanFor(std::vector<uint8_t> opcodesToFind, bool forward = true, int toSkip = 0) -> Scanner
        {
            const auto scanBytes = _address.GetAs<std::uint8_t*>();

            for (auto i = (forward ? 1 : -1); forward ? (i < 2048) : (i > -2048); forward ? i++ : i--)
            {
                bool found = true;

                for (int k = 0; k < opcodesToFind.size() && found; k++)
                {
                    if (opcodesToFind[k] == -1)
                        continue;
                    found = opcodesToFind[k] == scanBytes[i + k];
                }

                if (found)
                {
                    _address = &scanBytes[i];
                    if (toSkip != 0)
                    {
                        return ScanFor(opcodesToFind, forward, toSkip - 1);
                    }

                    break;
                }
            }

            return *this;
        }

        auto FindFunctionBoundary(bool forward = false) -> Scanner
        {
            const auto scanBytes = _address.GetAs<std::uint8_t*>();

            for (auto i = (forward ? 1 : -1); forward ? (i < 2048) : (i > -2048); forward ? i++ : i--)
            {
                if ( // ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::JMP_REL8) ||
                    // ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::JMP_REL32) ||
                    // ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::JMP_EAX) ||
                    ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::RETN_REL8) || ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::RETN) || ASM::byteIsA(scanBytes[i], ASM::MNEMONIC::INT3))
                {
                    _address = (uintptr_t)&scanBytes[i + 1];
                    break;
                }
            }

            return *this;
        }

        auto RelativeOffset(uint32_t offset) -> Scanner
        {
            _address.RelativeOffset(offset);

            return *this;
        }

        /* used to get the address of a non direct pointer ex: [rbx + 50] */
        auto AbsoluteOffset(uint32_t offset) -> Scanner
        {
            _address.AbsoluteOffset(offset);

            return *this;
        }

        template <typename T>
        auto GetAs() -> T
        {
            return _address.GetAs<T>();
        }

        auto Get() -> uintptr_t
        {
            return _address.Get();
        }

        auto IsValid() -> bool
        {
            return _address.IsValid();
        }
    };

    /* Bad don't use it tbh... */
    class TrampolineHook
    {
        void** originalFunctionPtr;
        PE::Address originalFunction;
        PE::Address hookFunction;
        PE::Address allocatedPage;
        std::vector<uint8_t> restore;

        void PointToCodeIfNot(PE::Address& ptr)
        {
            auto bytes = ptr.GetAs<std::uint8_t*>();

            if (ASM::byteIsA(bytes[0], ASM::MNEMONIC::JMP_REL32))
            {
                ptr = bytes + 5 + *(int32_t*)&bytes[1];
            }
        }

        void* AllocatePageNearAddress(void* targetAddr)
        {
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

            uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); // round down to nearest page boundary
            uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
            uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

            uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

            for (uint64_t pageOffset = 1; pageOffset; pageOffset++)
            {
                uint64_t byteOffset = pageOffset * PAGE_SIZE;
                uint64_t highAddr = startPage + byteOffset;
                uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

                bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

                if (highAddr < maxAddr)
                {
                    void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (outAddr)
                        return outAddr;
                }

                if (lowAddr > minAddr)
                {
                    void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (outAddr != nullptr)
                        return outAddr;
                }

                if (needsExit)
                {
                    break;
                }
            }

            return nullptr;
        }

        void WriteAbsoluteJump(void* jumpLocation, void* destination)
        {
            uint8_t absJumpInstructions[] = {
                ASM::Mnemonic("CMOVNS"), 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
                0x41, 0xFF, 0xE2 // jmp r10
            };

            auto destination64 = (uint64_t)destination;
            memcpy(&absJumpInstructions[2], &destination64, sizeof(destination64));
            memcpy(jumpLocation, absJumpInstructions, sizeof(absJumpInstructions));
        }

        uintptr_t PrepareRestore()
        {
            /*
                This is not a correct way to do it at all, since not all functions sub from the stack
                This needs so much more tests, but it works for now.
            */

            Scanner scanner(originalFunction);
            scanner.ScanFor({ 0x48, 0x83, 0xEC }); // sub rsp

            auto restoreSize = scanner.Get() - originalFunction.Get();

            MemcuryAssert(restoreSize > 0 && restoreSize < 0x100);

            restore.reserve(restoreSize);
            for (auto i = 0; i < restoreSize; i++)
            {
                restore.push_back(originalFunction.GetAs<uint8_t*>()[i]);
            }

            return restoreSize;
        }

        void WriteRestore()
        {
            auto restorePtr = allocatedPage + ASM::SIZE_OF_JMP_ABSLOUTE_INSTRUCTION + 2;

            memcpy(restorePtr.GetAs<void*>(), restore.data(), restore.size());

            *originalFunctionPtr = restorePtr.GetAs<void*>();

            // Write a jump back to where the execution should resume
            restorePtr.AbsoluteOffset((uint32_t)restore.size());

            auto contuineExecution = originalFunction + restore.size();

            WriteAbsoluteJump(restorePtr.GetAs<void*>(), contuineExecution.GetAs<void*>());
        }

        auto PrepareJMPInstruction(uint64_t dst)
        {
            uint8_t bytes[5] = { ASM::Mnemonic("JMP_REL32"), 0x0, 0x0, 0x0, 0x0 };

            const uint64_t relAddr = dst - (originalFunction.Get() + ASM::SIZE_OF_JMP_RELATIVE_INSTRUCTION);
            memcpy(bytes + 1, &relAddr, 4);

            return std::move(bytes);
        }

        bool IsHooked()
        {
            return originalFunction.GetAs<uint8_t*>()[0] == ASM::Mnemonic("JMP_REL32");
        }

    public:
        TrampolineHook(void** originalFunction, void* hookFunction)
        {
            this->originalFunctionPtr = originalFunction;

            this->originalFunction = *originalFunction;
            this->hookFunction = hookFunction;

            PointToCodeIfNot(this->originalFunction);
            PointToCodeIfNot(this->hookFunction);
        };

        bool Commit()
        {
            auto fnStart = originalFunction.GetAs<void*>();

            auto restoreSize = PrepareRestore();

            if (!allocatedPage.IsValid())
            {
                allocatedPage = AllocatePageNearAddress(fnStart);
            }

            memset(allocatedPage.GetAs<void*>(), ASM::MNEMONIC::INT3, 0x1000);

            WriteAbsoluteJump(allocatedPage.GetAs<void*>(), hookFunction.GetAs<void*>());

            DWORD oldProtect;
            VirtualProtect(fnStart, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

            auto jmpInstruction = PrepareJMPInstruction(allocatedPage.Get());

            WriteRestore();

            memset(fnStart, ASM::MNEMONIC::INT3, restoreSize);
            memcpy(fnStart, jmpInstruction, ASM::SIZE_OF_JMP_RELATIVE_INSTRUCTION);

            return true;
        }

        bool Revert()
        {
            auto fnStart = originalFunction.GetAs<void*>();

            DWORD oldProtect;
            VirtualProtect(fnStart, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

            memcpy(fnStart, restore.data(), restore.size());

            *originalFunctionPtr = originalFunction.GetAs<void*>();

            // VirtualFree(allocatedPage.GetAs<void*>(), 0x1000, MEM_RELEASE);

            return true;
        }

        auto Toggle()
        {
            if (IsHooked())
                Revert();
            else
                Commit();

            return IsHooked();
        }
    };

    namespace VEHHook
    {
        struct HOOK_INFO
        {
            void* Original;
            void* Detour;

            HOOK_INFO(void* Original, void* Detour)
                : Original(Original)
                , Detour(Detour)
            {
            }
        };

        inline std::vector<HOOK_INFO> Hooks;
        inline std::vector<DWORD> HookProtections;
        inline HANDLE ExceptionHandler;

        inline long Handler(EXCEPTION_POINTERS* Exception)
        {
            if (Exception->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
            {
                auto Itr = std::find_if(Hooks.begin(), Hooks.end(), [Rip = Exception->ContextRecord->Rip](const HOOK_INFO& Hook)
                    { return Hook.Original == (void*)Rip; });
                if (Itr != Hooks.end())
                {
                    Exception->ContextRecord->Rip = (uintptr_t)Itr->Detour;
                }

                Exception->ContextRecord->EFlags |= 0x100; // SINGLE_STEP_FLAG

                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else if (Exception->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
            {
                // TODO: find a way to only vp the function that about to get executed
                for (auto& Hook : Hooks)
                {
                    DWORD dwOldProtect;
                    VirtualProtect(Hook.Original, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOldProtect);
                }

                return EXCEPTION_CONTINUE_EXECUTION;
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }

        inline bool Init()
        {
            if (ExceptionHandler == nullptr)
            {
                ExceptionHandler = AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)Handler);
            }
            return ExceptionHandler != nullptr;
        }

        inline bool AddHook(void* Target, void* Detour)
        {
            if (ExceptionHandler == nullptr)
            {
                return false;
            }

            if (Util::IsSamePage(Target, Detour))
            {
                return false;
            }

            if (!VirtualProtect(Target, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &HookProtections.emplace_back()))
            {
                HookProtections.pop_back();
                return false;
            }

            Hooks.emplace_back(Target, Detour);
            return true;
        }

        inline bool RemoveHook(void* Original)
        {
            auto Itr = std::find_if(Hooks.begin(), Hooks.end(), [Original](const HOOK_INFO& Hook)
                { return Hook.Original == Original; });

            if (Itr == Hooks.end())
            {
                return false;
            }

            const auto ProtItr = HookProtections.begin() + std::distance(Hooks.begin(), Itr);
            Hooks.erase(Itr);

            DWORD dwOldProtect;
            bool Ret = VirtualProtect(Original, 1, *ProtItr, &dwOldProtect);
            HookProtections.erase(ProtItr);

            return false;
        }
    }
}