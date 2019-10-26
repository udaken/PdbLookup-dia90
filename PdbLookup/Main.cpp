
#include "pch.h"

#include <clocale>
#include <iostream>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <optional>
#include <limits>
#include <variant>
#include <unordered_map>

#define _WIN32_WINNT _WIN32_WINNT_WIN7                   
// // SDKDDKVer.h をインクルードすると、利用できる最も高いレベルの Windows プラットフォームが定義されます。
// 以前の Windows プラットフォーム用にアプリケーションをビルドする場合は、WinSDKVer.h をインクルードし、
// サポートしたいプラットフォームに _WIN32_WINNT マクロを設定してから SDKDDKVer.h をインクルードします。
#include <SDKDDKVer.h>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h> 
#include <dia2.h> 
#pragma comment(lib,"diaguids.lib")
//#import "dia2/dia2.tlb" auto_rename, no_namespace

#include <comip.h>
#include <comdef.h>
#include <comdefsp.h>
#include <dbghelp.h> // UNDNAME_COMPLETE

#include "CBcrypt.hpp"
#include "checked_cast.hpp"
#include "to_hexwstring.hpp"

typedef int _Bool;

#ifdef _MSC_VER
#define restrict __restrict 
#endif

EXTERN_C uint32_t UnDecorateStringSymbolName(
	const char* restrict name,
	unsigned char* restrict outputString,
	uint32_t maxStringLength,
	_Bool* restrict pisDoubleBytes);


using namespace std::string_literals;
using namespace std::literals::string_view_literals;
using std::begin;
using std::end;


constexpr std::size_t operator "" _z(unsigned long long n)
{
	return static_cast<std::size_t>(n);
}
constexpr std::uint8_t operator "" _u8(unsigned long long n)
{
	return static_cast<std::uint8_t>(n);
}

_COM_SMARTPTR_TYPEDEF(IDiaDataSource, __uuidof(IDiaDataSource));
_COM_SMARTPTR_TYPEDEF(IDiaSession, __uuidof(IDiaSession));
_COM_SMARTPTR_TYPEDEF(IDiaSymbol, __uuidof(IDiaSymbol));
_COM_SMARTPTR_TYPEDEF(IDiaEnumTables, __uuidof(IDiaEnumTables));
_COM_SMARTPTR_TYPEDEF(IDiaTable, __uuidof(IDiaTable));
_COM_SMARTPTR_TYPEDEF(IDiaEnumSymbols, __uuidof(IDiaEnumSymbols));
_COM_SMARTPTR_TYPEDEF(IDiaLineNumber, __uuidof(IDiaLineNumber));
_COM_SMARTPTR_TYPEDEF(IDiaEnumLineNumbers, __uuidof(IDiaEnumLineNumbers));
_COM_SMARTPTR_TYPEDEF(IDiaSourceFile, __uuidof(IDiaSourceFile));
_COM_SMARTPTR_TYPEDEF(IDiaEnumSourceFiles, __uuidof(IDiaEnumSourceFiles));


inline void throw_if_failed(HRESULT hr, LPCTSTR message = nullptr)
{
	if (FAILED(hr))
	{
		throw _com_error(hr);
	}
}

template <int width = 1>
inline std::wstring to_wstring(unsigned long val)
{
	wchar_t buf[std::max(std::numeric_limits<decltype(val)>::digits10 + 1, width) + 1];
	std::swprintf(buf, std::size(buf), L"%*lu", width, val);
	return buf;
}

template <class CharT, class AlgTraits = std::char_traits<CharT> >
inline constexpr bool starts_with(std::basic_string_view<CharT, AlgTraits> s, std::basic_string_view<CharT, AlgTraits>  x) noexcept
{
	return s.size() >= x.size() && s.compare(0, x.size(), x) == 0;
}

template <class CharT, class AlgTraits = std::char_traits<CharT> >
inline constexpr bool starts_with(const CharT *s, std::basic_string_view<CharT, AlgTraits>  x) noexcept
{
	return starts_with(std::basic_string_view<CharT>(s), x);
}

std::ostream& operator <<(std::ostream& ros, const _bstr_t &str) {
	return ros << (const wchar_t*)str;
}

class CCoInitialize final
{
public:
	HRESULT const m_hr;

	CCoInitialize(const CCoInitialize&) = delete;
	CCoInitialize& operator=(const CCoInitialize&) = delete;

	CCoInitialize()
		: m_hr(::CoInitialize(nullptr))
	{
	}

	~CCoInitialize()
	{
		::CoUninitialize();
	};

};

using module_handle_t = std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&::FreeLibrary)>;

auto make_module_handle(HMODULE hModule)
{
	return module_handle_t{ hModule, &::FreeLibrary };
}

using win32_handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&::CloseHandle)>;
using win32_shared_handle = std::shared_ptr<std::remove_pointer_t<HANDLE>>;

win32_handle make_win32_handle(HANDLE h) noexcept
{
	return { (h == INVALID_HANDLE_VALUE ? nullptr : h), ::CloseHandle };
}

static constexpr LPCWSTR tagNames[SymTagMax] = {
	L"Null",
	L"Exe",
	L"Compiland",
	L"CompilandDetails",
	L"CompilandEnv",
	L"Function",
	L"Block",
	L"Data",
	L"Annotation",
	L"Label",
	L"PublicSymbol",
	L"UDT",
	L"Enum",
	L"FunctionType",
	L"PointerType",
	L"ArrayType",
	L"BaseType",
	L"Typedef",
	L"BaseClass",
	L"Friend",
	L"FunctionArgType",
	L"FuncDebugStart",
	L"FuncDebugEnd",
	L"UsingNamespace",
	L"VTableShape",
	L"VTable",
	L"Custom",
	L"Thunk",
	L"CustomType",
	L"ManagedType",
	L"Dimension",
};

#define GET_DIA_SYMBOL_PROPERTY_OPT(_type, _name, _pSymbol) \
	std::optional<_type> _name; \
	{ \
		_type tmp; \
		HRESULT hr = (_pSymbol)->get_ ## _name(&tmp); \
		if(hr == S_OK) _name = tmp; \
		else throw_if_failed(hr); \
	}

#define GET_DIA_SYMBOL_PROPERTY_PTR(_type, _name, _pSymbol) \
	_type _name; \
	throw_if_failed((_pSymbol)->get_ ## _name(&_name));

#define GET_DIA_SYMBOL_PROPERTY_BSTR(_name, _pSymbol) \
	_bstr_t _name; \
	throw_if_failed(_pSymbol->get_ ## _name(_name.GetAddress()));

struct SymbolInfo
{
	std::wstring name;
	std::optional<DWORD> relativeVirtualAddress;
	ULONGLONG length;
	std::wstring undecoratedName;
	std::wstring sourceFileName;
	enum SymTagEnum symTag;
	bool code;
	bool function;
	std::optional<std::tuple<DWORD, DWORD>> address;
	std::optional<ULONGLONG> virtualAddress;

	inline std::optional<ULONGLONG> endOfRVA() const
	{
		if (relativeVirtualAddress && length)
			return relativeVirtualAddress.value() + length - 1;
		else
			return {};
	}
	inline std::optional<ULONGLONG> endOfVA() const
	{
		if (virtualAddress && length)
			return virtualAddress.value() + length - 1;
		else
			return {};
	}
	inline std::wstring addressStr() const
	{
		return (address) ?
			(to_hexwstring<4>(std::get<0>(*address)) + L":" + to_hexwstring<8>(std::get<1>(*address))) : L"#N/A";
	}
};

struct Context
{
	_bstr_t filePath;
	std::wstring pdbpath;
	// set default base address.The default for Windows CE EXEs is 0x00010000.
	ULONGLONG loadAddress = 0x00010000ull;
	std::vector<LPCTSTR> args;
};

std::vector<uint8_t> get_hash_from_file(LPCWSTR path, bool sha1) {
	CBcryptAlg alg;
	alg.Open(sha1 ? CBcryptAlg::Sha1Traits::ProviderName : CBcryptAlg::Md5Traits::ProviderName);
	CBcryptHash hash;
	alg.CreateHash(hash);
	constexpr auto bufSize = 8 * 1024 * 1024u;
	const auto buf = std::make_unique<BYTE[]>(bufSize);
	auto hFile = make_win32_handle(::CreateFile(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (!hFile)
	{
		return {};
	}

	for (;;)
	{
		DWORD dwRead = 0;
		BOOL success = ::ReadFile(hFile.get(), buf.get(), bufSize, &dwRead, nullptr);
		if (!success)
		{
			return {};
		}
		else if (dwRead > 0)
		{
			hash.Update(buf.get(), dwRead);
		}
		else
		{
			break;
		}
	}
	hash.Finish();
	return hash.GetHashData();
}

std::vector<std::string> get_all_lines_from_file(LPCWSTR path) {
	std::vector<std::string> allLines;
	std::ifstream ifs{ path, std::ios::in };
	while (ifs.good()) {
		std::string line;
		if (std::getline(ifs, line)) {
			allLines.push_back(line);
		}
	}
	return allLines;
}

void PrintSymbolAsCsv(const std::vector<SymbolInfo> &list)
{
	std::wcout
		<< L"\"section:addres\"" << L","
		<< L"\"RVA\"" << L","
		<< L"\"EndOfRVA\"" << L","
		<< L"\"length\"" << L","
		<< L"\"Type\"" << L","
		<< L"\"Name\"" << L","
		<< L"\"UndecoratedName\"" << L","
		<< L"\"SourceFile\"" << L","
		<< L"\"VA\"" << L","
		<< L"\"EndOfVA\"" << L","
		<< L"\n";

	for (auto &&entry : list)
	{
		std::wcout
			<< L'"' << entry.addressStr() << L'"' << L","
			<< L'"' << (entry.relativeVirtualAddress ? (L"0x" + to_hexwstring<8>(entry.relativeVirtualAddress.value())) : L"") << L'"' << L","
			<< L'"' << (entry.endOfRVA() ? (L"0x" + to_hexwstring<8>(entry.endOfRVA().value())) : L"") << L'"' << L","
			<< std::to_wstring(entry.length) << L","
			<< L'"' << tagNames[entry.symTag] << L'"' << L","
			<< L'"' << entry.name << L'"' << L","
			<< L'"' << entry.undecoratedName << L'"' << L","
			<< L'"' << entry.sourceFileName << L'"' << L","
			<< L'"' << (entry.virtualAddress ? L"0x" + to_hexwstring<8>(entry.virtualAddress.value()) : L"") << L'"' << L","
			<< L'"' << (entry.endOfVA() ? L"0x" + to_hexwstring<8>(entry.endOfVA().value()) : L"") << L'"' << L","
			<< L"\n";
	}
}

enum {
	ChecksumTypeMd5 = 1,
	ChecksumTypeSha1 = 2,
};

int LookupSymbol(IDiaSession* pSession, Context &context)
{
	ULONGLONG va = ULLONG_MAX;
	bool relative = false;
	constexpr auto vastr = L"--va="sv;
	constexpr auto rvastr = L"--rva="sv;
	for (auto &&i : context.args)
	{
		if (starts_with(i, vastr))
		{
			va = std::stoull(i + vastr.length(), nullptr, 16);
		}
		else if (starts_with(i, rvastr))
		{
			va = std::stoull(i + rvastr.length(), nullptr, 16);
			relative = true;
		}
		else
		{
			std::wcerr << L"unknown option. `" << i << L"`\n";
			return EXIT_FAILURE;
		}
	}
	if (va == ULLONG_MAX)
	{
		std::wcerr << L"must specified " << vastr << L"XXXXXXXX or " << rvastr << L"XXXXXXXX\n";
		return EXIT_FAILURE;
	}
	{
		IDiaSymbolPtr pSymbol;
		long displacement = 0;
		if (relative)
			throw_if_failed(pSession->findSymbolByRVAEx(checked_cast<DWORD>(va), SymTagNull, &pSymbol, &displacement));
		else
			throw_if_failed(pSession->findSymbolByVAEx(va, SymTagNull, &pSymbol, &displacement));

		GET_DIA_SYMBOL_PROPERTY_BSTR(name, pSymbol);

		std::wcout << to_hexwstring<8>(va) << L":" << name << L"+0x" << to_hexwstring(displacement)
			<< L"\n";
	}
	{
		IDiaEnumLineNumbersPtr pLineNumsPtr;
		if (relative)
			throw_if_failed(pSession->findLinesByRVA(checked_cast<DWORD>(va), 1, &pLineNumsPtr));
		else
			throw_if_failed(pSession->findLinesByVA(va, 1, &pLineNumsPtr));

		IDiaLineNumberPtr pLineNumPtr;
		ULONG celt;
		ULONG cnt = 0;
		while (SUCCEEDED(pLineNumsPtr->Next(1, &pLineNumPtr, &celt)) && celt == 1)
		{
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, length, pLineNumPtr);

			IDiaSourceFilePtr sourceFile;
			throw_if_failed(pLineNumPtr->get_sourceFile(&sourceFile));

			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, checksumType, sourceFile);
			std::vector<BYTE> buf;
			buf.resize(
				checksumType.value() == ChecksumTypeMd5 ? 16_z :
				checksumType.value() == ChecksumTypeSha1 ? 20_z :
				1_z,
				0xFF_u8
			);
			DWORD cbData;
			throw_if_failed(sourceFile->get_checksum(checked_cast<DWORD>(buf.capacity()), &cbData, buf.data()));

			GET_DIA_SYMBOL_PROPERTY_BSTR(fileName, sourceFile);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, lineNumber, pLineNumPtr);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, lineNumberEnd, pLineNumPtr);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, columnNumber, pLineNumPtr);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, columnNumberEnd, pLineNumPtr);

			auto currentHashValue = get_hash_from_file((LPCWSTR)fileName, checksumType.value() == ChecksumTypeSha1);
			_bstr_t line;
			if (!std::equal(buf.begin(), buf.end(), currentHashValue.cbegin()))
			{
				line = L"<hash value miss match>";
			}

			auto allLines = get_all_lines_from_file((LPCWSTR)fileName);
			if (lineNumber && lineNumber.value() < allLines.size() + 1)
			{
				line +=
					allLines.at(lineNumber.value() - 1).c_str();
			}
			else
			{
				line += L"#N/A";
			}

			std::wcout << to_wstring<4>(++cnt) << L":" << fileName << L"(" << lineNumber.value() << L"): " << line << "\n";
		}
	}

	return EXIT_SUCCESS;
}

std::variant< std::string, std::wstring> DemangleStringConstants(LPCSTR symbolName)
{
	_Bool isUtf16Be = false;
	auto length = UnDecorateStringSymbolName(symbolName, nullptr, 0, &isUtf16Be);
	if (length)
	{
		std::vector<uint8_t> buf(length);
		if (UnDecorateStringSymbolName(symbolName, buf.data(), length, &isUtf16Be))
		{
			if (isUtf16Be)
			{
				std::wstring str;
				for (decltype(length) i = 0; i < length; i += 2)
				{
					str.push_back(wchar_t(buf.at(i) << 8 | buf.at(i + 1)));
				}
				return str;
			}
			else
			{
				return std::string{ reinterpret_cast<char*>(buf.data()), length / sizeof(wchar_t) };
			}
		}
	}

	return symbolName;
}

int PrintAllymbols(IDiaSession* pSession, Context &context)
{
	for (auto &&i : context.args)
	{
		std::wcerr << L"unknown option. `" << i << L"`\n";
		return EXIT_FAILURE;
	}

	IDiaSymbolPtr pGlobalSym;
	throw_if_failed(pSession->get_globalScope(&pGlobalSym));

	std::vector<SymbolInfo> list;
	{
		IDiaEnumSymbolsPtr pEnumSymbol;
		throw_if_failed(pGlobalSym->findChildren(SymTagNull, L"*", nsCaseInRegularExpression, &pEnumSymbol));

		LONG symbolCount;
		throw_if_failed(pEnumSymbol->get_Count(&symbolCount));

		IDiaSymbolPtr pSymbol;
		ULONG celt;
		while (SUCCEEDED(pEnumSymbol->Next(1, &pSymbol, &celt)) && celt == 1)
		{
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, symIndexId, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, symTag, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_BSTR(name, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_PTR(IDiaSymbolPtr, lexicalParent, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_PTR(IDiaSymbolPtr, classParent, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_PTR(IDiaSymbolPtr, type, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, dataKind, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, locationType, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, addressSection, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, addressOffset, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, relativeVirtualAddress, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(ULONGLONG, virtualAddress, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, registerId, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(LONG, offset, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(ULONGLONG, length, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, slot, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, volatileType, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, constType, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, unalignedType, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, access, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_BSTR(libraryName, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, platform, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, language, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, editAndContinueEnabled, pSymbol);
			//GET_DIA_SYMBOL_PROPERTY(DWORD, frontEndMajor, pSymbol);
			//GET_DIA_SYMBOL_PROPERTY(DWORD, frontEndMinor, pSymbol);
			//GET_DIA_SYMBOL_PROPERTY(DWORD, frontEndBuild, pSymbol);
			//GET_DIA_SYMBOL_PROPERTY(DWORD, backEndMajor, pSymbol);
			//GET_DIA_SYMBOL_PROPERTY(DWORD, backEndMinor, pSymbol);
			//GET_DIA_SYMBOL_PROPERTY(DWORD, backEndBuild, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_BSTR(sourceFileName, pSymbol);
			//unused
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, thunkOrdinal, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, virtualBaseOffset, pSymbol);
			//virtual
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, pure, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, callingConvention, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(VARIANT, value, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, baseType, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, token, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, timeStamp, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(GUID, guid, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_BSTR(symbolsFileName, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, reference, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, count, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, bitPosition, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_PTR(IDiaSymbolPtr, arrayIndexType, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, packed, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, constructor, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, overloadedOperator, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, nested, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasNestedTypes, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasAssignmentOperator, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasCastOperator, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, scoped, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, virtualBaseClass, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, indirectVirtualBaseClass, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(LONG, virtualBasePointerOffset, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_PTR(IDiaSymbolPtr, virtualTableShape, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, lexicalParentId, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, classParentId, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, typeId, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, arrayIndexTypeId, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, virtualTableShapeId, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, code, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, function, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, managed, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, msil, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, virtualBaseDispIndex, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_BSTR(undecoratedName, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, age, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, signature, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, compilerGenerated, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, addressTaken, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, rank, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_PTR(IDiaSymbolPtr, lowerBound, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_PTR(IDiaSymbolPtr, upperBound, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, lowerBoundId, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, upperBoundId, pSymbol);

			std::optional<DWORD> dataByteLength;
			{
				DWORD tmp = 0;
				HRESULT hr = pSymbol->get_dataBytes(0, &tmp, nullptr);
				if (hr == S_OK) dataByteLength = tmp;
			}

			// dataBytes
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, targetSection, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, targetOffset, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, targetRelativeVirtualAddress, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(ULONGLONG, targetVirtualAddress, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, machineType, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, oemId, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, oemSymbolId, pSymbol);
			// types
			// typeIds
			GET_DIA_SYMBOL_PROPERTY_PTR(IDiaSymbolPtr, objectPointerType, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(DWORD, udtKind, pSymbol);
			// undecoratedNameEx
			// liveLVarInstances
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, noReturn, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, noInline, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, optimizedCodeDebugInfo, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, notReached, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, interruptReturn, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, farReturn, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isStatic, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasDebugInfo, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isLTCG, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isDataAligned, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasSecurityChecks, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_BSTR(compilerName, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasAlloca, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasSetJump, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasLongJump, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasInlAsm, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasEH, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasSEH, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasEHa, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isNaked, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isAggregated, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isSplitted, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_PTR(IDiaSymbolPtr, container, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, inlSpec, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, noStackOrdering, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_PTR(IDiaSymbolPtr, virtualBaseTableType, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, hasManagedCode, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isHotpatchable, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isCVTCIL, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isMSILNetmodule, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isCTypes, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isStripped, pSymbol);
			//GET_DIA_SYMBOL_PROPERTY(DWORD, frontEndQFE, pSymbol);
			//GET_DIA_SYMBOL_PROPERTY(DWORD, backEndQFE, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, wasInlined, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, strictGSCheck, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isCxxReturnUdt, pSymbol);
			GET_DIA_SYMBOL_PROPERTY_OPT(BOOL, isConstructorVirtualBase, pSymbol);

			std::optional<BOOL> isVirtual;
			{
				BOOL tmp;
				auto hr = pSymbol->get_virtual(&tmp);
				if (hr == S_OK) isVirtual = tmp;
				else throw_if_failed(hr);
			}

			_bstr_t undecoratedNameEx;
			throw_if_failed(pSymbol->get_undecoratedNameEx(UNDNAME_COMPLETE, undecoratedNameEx.GetAddress()));

			list.emplace_back(SymbolInfo{
				(LPCWSTR)name,
				relativeVirtualAddress,
				length.value_or(0),
				(undecoratedNameEx.length() > 0 ? (LPCWSTR)undecoratedNameEx : L""),
				(sourceFileName.length() > 0 ? (LPCWSTR)sourceFileName : L""),
				static_cast<enum SymTagEnum>(symTag.value()),
				code != FALSE,
				function != FALSE,
				(addressSection && addressOffset) ? std::make_optional(std::make_tuple(*addressSection, *addressOffset)) : decltype(SymbolInfo::address){},
				virtualAddress,
				});
		}
	}

	std::stable_sort(list.begin(), list.end(),
		[](auto const &left, auto const &right)->bool {
		return
			std::less{}(left.address, right.address) &&
			std::less{}(left.relativeVirtualAddress, right.relativeVirtualAddress);
	});

	// fix length
	for (size_t i = 1; i < list.size(); ++i)
	{
		auto &&before = list[i - 1];
		auto &&info = list[i];
		if (before.address && info.address)
		{
			auto &&[beforeSection, beforeOffset] = *before.address;
			auto &&[addressSection, addressOffset] = *info.address;
			if (beforeSection == addressSection && beforeOffset < addressOffset)
			{
				before.length = addressOffset - beforeOffset;
			}
		}
	}

	PrintSymbolAsCsv(list);

	return EXIT_SUCCESS;
}

constexpr auto commandName = L"PdbLookup"sv;

int ShowHelp(IDiaSession*, Context &);
using fpCommand_t = int (*)(IDiaSession* pSession, Context &context);

constexpr struct {
	LPCWSTR name;
	fpCommand_t f;
	LPCWSTR description;
} subCommandTable[] = {
	{L"map", &PrintAllymbols, L"Show symbol map."},
	{L"lookup", &LookupSymbol,L"Lookup symbol from VA(or RVA)."},
	{L"help", nullptr, L"Show this text."},
};

int ShowHelp()
{
	std::wcerr << commandName << L" subcommand <module-path> [options]" << std::endl;
	std::wcerr << L"sub command:" << std::endl;
	for (auto &&i : subCommandTable)
	{
		std::wcerr << L"  " << i.name << L"\t" << i.description << std::endl;
	}
	std::wcerr << L"options:" << std::endl;
	std::wcerr << L"  --pdbpath <path to dir>" << std::endl;
	std::wcerr << L"  --loadaddr=addr" << std::endl;
	std::wcerr << L"  --out <path>" << std::endl;
	return EXIT_FAILURE;
}

int Setup(int argc, TCHAR *argv[], fpCommand_t &fpCommand, Context &c)
{
	if (argc <= 1)
	{
		fpCommand = nullptr;
	}
	else
	{
		for (auto &&i : subCommandTable)
		{
			if (wcscmp(argv[1], i.name) == 0)
				fpCommand = i.f;
		}
	}

	if (fpCommand == nullptr)
	{
		ShowHelp();
		return EXIT_FAILURE;
	}

	if (argc <= 2)
	{
		std::wcerr << L"must specified filepath.\n";
		return EXIT_FAILURE;
	}
	c.filePath = argv[2];

	// set default base address.The default for Windows CE EXEs is 0x00010000.
	for (int i = 3; i < argc; ++i)
	{
		if (wcscmp(argv[i], L"--pdbpath") == 0)
		{
			if (i + 1 < argc)
			{
				c.pdbpath = argv[++i];
			}
			else
			{
				std::wcerr << L"missing args.:`--pdbath <path>`" << L"\n";
				return EXIT_FAILURE;
			}
		}
		else if (starts_with(argv[i], L"--loadaddr="sv))
		{
			c.loadAddress = std::stoull(argv[i] + (L"--loadaddr="sv).length(), nullptr, 16);
		}
		else if (starts_with(argv[i], L"--out"sv))
		{
			if (i + 1 < argc)
			{
				FILE *fp = nullptr;
				if (_wfreopen_s(&fp, argv[++i], L"w", stdout) != 0)
				{
					std::wcerr << L"can't set output to `" << argv[i] << L"`" << L"\n";
					return EXIT_FAILURE;
				}
			}
			else
			{
				std::wcerr << L"missing args.:`--out <path>`" << L"\n";
				return EXIT_FAILURE;
			}
		}
		else
		{
			c.args.push_back(argv[i]);
		}
	}
	return EXIT_SUCCESS;
}


std::optional<ULONGLONG> GetImageBaseFromPE(LPCWSTR path)
{
	auto hFile = make_win32_handle(::CreateFile(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));

	static constexpr BYTE magic[] = { 'P','E','\0','\0' };
	DWORD read{};
	IMAGE_DOS_HEADER dosHeader{};
	IMAGE_NT_HEADERS header{};
	if (hFile && ::ReadFile(hFile.get(), &dosHeader, sizeof(dosHeader), &read, nullptr) && read == sizeof(dosHeader))
	{
		if (SetFilePointer(hFile.get(), dosHeader.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
		{
			if (::ReadFile(hFile.get(), &header, sizeof(header), &read, nullptr) && read == sizeof(header) &&
				(memcmp(&header.Signature, magic, sizeof(magic)) == 0) &&
				header.FileHeader.SizeOfOptionalHeader >= sizeof(header.OptionalHeader))
			{
				return header.OptionalHeader.ImageBase;
			}
		}
	}
	std::wcerr << "warning: Can't get ImageBase.";
	return {};
}

int wmain(int argc, TCHAR *argv[])
try
{
	std::setlocale(LC_ALL, "");

	fpCommand_t fpCommand = nullptr;
	Context c{};

	if (Setup(argc, argv, fpCommand, c) != EXIT_SUCCESS)
	{
		return EXIT_FAILURE;
	}

	CCoInitialize init;
	throw_if_failed(init.m_hr);

	auto msdiaModule = make_module_handle(::LoadLibrary(L"msdia90.dll"));
	{
		IDiaDataSourcePtr pDataSource;
		if (msdiaModule == nullptr)
		{
			throw_if_failed(pDataSource.CreateInstance(__uuidof(DiaSource)));
		}
		else
		{
			auto fpDllGetClassObject = reinterpret_cast<LPFNGETCLASSOBJECT>(::GetProcAddress(msdiaModule.get(), "DllGetClassObject"));
			if (fpDllGetClassObject == nullptr)
				throw_if_failed(HRESULT_FROM_WIN32(::GetLastError()));

			IClassFactoryPtr factory;
			throw_if_failed(fpDllGetClassObject(__uuidof(DiaSource), IID_PPV_ARGS(&factory)));
			throw_if_failed(factory->CreateInstance(nullptr, IID_PPV_ARGS(&pDataSource)));
		}

		if (FAILED(pDataSource->loadDataFromPdb(c.filePath)))
		{
			throw_if_failed(pDataSource->loadDataForExe(c.filePath, (c.pdbpath.length() > 0 ? c.pdbpath.c_str() : nullptr),
				nullptr), L"PDBファイルの読み込みに失敗しました。");

			auto imageBase = GetImageBaseFromPE(c.filePath);
			if (imageBase)
				c.loadAddress = imageBase.value();
		}

		IDiaSessionPtr pSession;
		throw_if_failed(pDataSource->openSession(&pSession));

		throw_if_failed(pSession->put_loadAddress(c.loadAddress));

		IDiaSymbolPtr pSymbol;
		throw_if_failed(pSession->get_globalScope(&pSymbol));

		int result = fpCommand(pSession, c);
		return result;
	}
}
catch (const _com_error& e)
{
	const static std::unordered_map<HRESULT, LPCTSTR> dia_errors = {
		{E_PDB_OK, L"E_PDB_OK"},
		{E_PDB_USAGE, L"E_PDB_USAGE"},
		{E_PDB_OUT_OF_MEMORY, L"E_PDB_OUT_OF_MEMORY"},
		{E_PDB_FILE_SYSTEM, L"E_PDB_FILE_SYSTEM"},
		{E_PDB_NOT_FOUND, L"E_PDB_NOT_FOUND"},
		{E_PDB_INVALID_SIG, L"E_PDB_INVALID_SIG"},
		{E_PDB_INVALID_AGE, L"E_PDB_INVALID_AGE"},
		{E_PDB_PRECOMP_REQUIRED, L"E_PDB_PRECOMP_REQUIRED"},
		{E_PDB_OUT_OF_TI, L"E_PDB_OUT_OF_TI"},
		{E_PDB_NOT_IMPLEMENTED, L"E_PDB_NOT_IMPLEMENTED"},
		{E_PDB_V1_PDB, L"E_PDB_V1_PDB"},
		{E_PDB_FORMAT, L"E_PDB_FORMAT"},
		{E_PDB_LIMIT, L"E_PDB_LIMIT"},
		{E_PDB_CORRUPT, L"E_PDB_CORRUPT"},
		{E_PDB_TI16, L"E_PDB_TI16"},
		{E_PDB_ACCESS_DENIED, L"E_PDB_ACCESS_DENIED"},
		{E_PDB_ILLEGAL_TYPE_EDIT, L"E_PDB_ILLEGAL_TYPE_EDIT"},
		{E_PDB_INVALID_EXECUTABLE, L"E_PDB_INVALID_EXECUTABLE"},
		{E_PDB_DBG_NOT_FOUND, L"E_PDB_DBG_NOT_FOUND"},
		{E_PDB_NO_DEBUG_INFO, L"E_PDB_NO_DEBUG_INFO"},
		{E_PDB_INVALID_EXE_TIMESTAMP, L"E_PDB_INVALID_EXE_TIMESTAMP"},
		{E_PDB_RESERVED, L"E_PDB_RESERVED"},
		{E_PDB_DEBUG_INFO_NOT_IN_PDB, L"E_PDB_DEBUG_INFO_NOT_IN_PDB"},
		{E_PDB_SYMSRV_BAD_CACHE_PATH, L"E_PDB_SYMSRV_BAD_CACHE_PATH"},
		{E_PDB_SYMSRV_CACHE_FULL, L"E_PDB_SYMSRV_CACHE_FULL"},
	};

	auto && i = dia_errors.find(e.Error());

	std::wcerr << (i != dia_errors.end()) ? i->second : e.ErrorMessage();
	return EXIT_FAILURE;
}
catch (const std::exception& e)
{
	std::wcerr << e.what();
	return EXIT_FAILURE;
}


