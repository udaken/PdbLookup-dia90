#pragma once

#include <windows.h>
#include <bcrypt.h>
#pragma comment (lib, "bcrypt.lib")

class CBcryptHash;
struct CBcryptPsudoHandles;

struct CBCryptException final
{
	NTSTATUS m_status;
};

#if CBCRYPT_NO_EXCEPTION
#define CBCRYPT_RESULT NTSTATUS

#define CBCRYPT_CHECK CBCRYPT_CHECK_NTSTATUS
#define CBCRYPT_CHECK_NTSTATUS(_exp) \
	do{ \
	NTSTATUS status = (_exp); \
	if(!BCRYPT_SUCCESS(status)) {\
	  return status;\
	} \
	}while(0)

#define CBCRYPT_RETURN(_exp) \
	return (_exp)

#define CBCRYPT_RETURN_NTSTATUS CBCRYPT_RETURN
#else
using CBCRYPT_RESULT = void;

#define CBCRYPT_CHECK(_exp) _exp

inline void CBCRYPT_CHECK_NTSTATUS(NTSTATUS status)
{
	if (!BCRYPT_SUCCESS(status)) {
		CBCryptException ex{ status };
		throw ex;
	}
};

#define CBCRYPT_RETURN(_exp) \
	CBCRYPT_CHECK(_exp);return

#define CBCRYPT_RETURN_NTSTATUS(_exp) \
	CBCRYPT_CHECK_NTSTATUS(_exp);return
#endif

class CBcryptAlg final
{
	BCRYPT_ALG_HANDLE m_handle = nullptr;
private:
	constexpr explicit CBcryptAlg(BCRYPT_ALG_HANDLE handle) noexcept : m_handle(handle)
	{}

public:
	struct Md5Traits {
		static constexpr auto ProviderName = BCRYPT_MD5_ALGORITHM;
		static constexpr ULONG hashSize = 128u / 8;
	};

	struct Sha1Traits {
		static constexpr auto ProviderName = BCRYPT_SHA1_ALGORITHM;
		static constexpr ULONG hashSize = 160u / 8;
	};

	constexpr CBcryptAlg() noexcept {}
	CBcryptAlg(const CBcryptAlg&) = delete;
	CBcryptAlg& operator=(const CBcryptAlg&) = delete;

	~CBcryptAlg() noexcept
	{
		if (m_handle && (reinterpret_cast<uintptr_t>(m_handle) % 16) != 1)
			::BCryptCloseAlgorithmProvider(m_handle, 0);
	}

	CBCRYPT_RESULT Open(
		LPCWSTR           pszAlgId,
		LPCWSTR           pszImplementation = nullptr,
		DWORD             dwFlags = 0)
	{
		CBCRYPT_RETURN_NTSTATUS(::BCryptOpenAlgorithmProvider(&m_handle, pszAlgId, pszImplementation, dwFlags));
	}

	CBCRYPT_RESULT GetProperty(
		LPCWSTR       pszProperty,
		PUCHAR        pbOutput,
		ULONG         cbOutput,
		ULONG         *pcbResult,
		ULONG         dwFlags = 0)
	{
		CBCRYPT_RETURN_NTSTATUS(::BCryptGetProperty(m_handle, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags));
	}

	CBCRYPT_RESULT GetObjectLength(DWORD *dwHashObjectSize)
	{
		ULONG cbResult;
		CBCRYPT_RETURN(GetProperty(BCRYPT_OBJECT_LENGTH, (LPBYTE)dwHashObjectSize, sizeof(*dwHashObjectSize), &cbResult));
	}

	CBCRYPT_RESULT GetHashLength(DWORD *pdwHashDataSize)
	{
		ULONG cbResult;
		CBCRYPT_RETURN(GetProperty(BCRYPT_HASH_LENGTH, (LPBYTE)pdwHashDataSize, sizeof(*pdwHashDataSize), &cbResult));
	}

	CBCRYPT_RESULT Hash(
		const UCHAR*      pbInput,
		ULONG             cbInput,
		PUCHAR            pbOutput,
		ULONG             cbOutput,
		PUCHAR            pbSecret = nullptr,
		ULONG             cbSecret = 0);

	template <class AlgTraits>
	static CBCRYPT_RESULT GetHashValue(
		const UCHAR*      pbInput,
		ULONG             cbInput,
		UCHAR(&pbOutput)[AlgTraits::hashSize])
	{
		CBcryptAlg alg;
		CBCRYPT_CHECK(alg.Open(AlgTraits::ProviderName));
		CBCRYPT_RETURN(alg.Hash(pbInput, cbInput, pbOutput, AlgTraits::hashSize));
	}

	static CBCRYPT_RESULT GetMd5Value(
		const UCHAR*      pbInput,
		ULONG             cbInput,
		UCHAR(&pbOutput)[Md5Traits::hashSize]) {
		CBCRYPT_RETURN(GetHashValue<Md5Traits>(pbInput, cbInput, pbOutput));
	}

	static CBCRYPT_RESULT GetSha1Value(
		const UCHAR*      pbInput,
		ULONG             cbInput,
		UCHAR(&pbOutput)[Sha1Traits::hashSize]) {
		CBCRYPT_RETURN(GetHashValue<Sha1Traits>(pbInput, cbInput, pbOutput));
	}

	CBCRYPT_RESULT CreateHash(
		CBcryptHash & hash,
		PUCHAR             pbHashObject
#if (NTDDI_VERSION >= NTDDI_WIN7)
		= nullptr
#endif
		,
		ULONG              cbHashObject
#if (NTDDI_VERSION >= NTDDI_WIN7)
		= 0
#endif
		,
		PUCHAR             pbSecret = nullptr,
		ULONG              cbSecret = 0,
		ULONG              dwFlags = 0);

	template <class AlgTraits>
	static CBCRYPT_RESULT GetAlg(
		CBcryptAlg & alg)
	{
		CBCRYPT_RETURN(alg.Open(AlgTraits::Name));
	}
};

class CBcryptHash final
{
	friend class CBcryptAlg;
	BCRYPT_HASH_HANDLE m_handle = nullptr;
	std::vector<uint8_t> m_HashData;
public:
	CBcryptHash() noexcept {}
	CBcryptHash(const CBcryptHash&) = delete;
	CBcryptHash& operator=(const CBcryptHash&) = delete;
	~CBcryptHash() noexcept
	{
		if (m_handle)
			::BCryptDestroyHash(m_handle);
	}

	CBCRYPT_RESULT Update(
		const UCHAR*       pbInput,
		ULONG              cbInput,
		ULONG              dwFlags = 0)
	{
		CBCRYPT_RETURN_NTSTATUS(::BCryptHashData(m_handle, const_cast<PUCHAR>(pbInput), cbInput, dwFlags));
	}
	CBCRYPT_RESULT Finish()
	{
		// cbOutput must same the hash size
		CBCRYPT_RETURN_NTSTATUS(::BCryptFinishHash(m_handle, m_HashData.data(), static_cast<ULONG>(m_HashData.size()), 0));
	}
	auto& GetHashData() const
	{
		return m_HashData;
	}
};

inline CBCRYPT_RESULT CBcryptAlg::CreateHash(
	CBcryptHash & hash,
	PUCHAR             pbHashObject,
	ULONG              cbHashObject,
	PUCHAR             pbSecret,
	ULONG              cbSecret,
	ULONG              dwFlags)
{
	DWORD HashLength;
	CBCRYPT_CHECK(this->GetHashLength(&HashLength));
	hash.m_HashData.resize(HashLength, 0xCC);
	CBCRYPT_RETURN_NTSTATUS(::BCryptCreateHash(m_handle, &hash.m_handle, pbHashObject, cbHashObject, pbSecret, cbSecret, dwFlags));
}

inline CBCRYPT_RESULT CBcryptAlg::Hash(
	const UCHAR*      pbInput,
	ULONG             cbInput,
	PUCHAR            pbOutput,
	ULONG             cbOutput,
	PUCHAR            /*pbSecret*/,
	ULONG             /*cbSecret*/)
{
	CBcryptHash hash;
	CBCRYPT_CHECK(this->CreateHash(hash));
	CBCRYPT_CHECK(hash.Update(pbInput, cbInput));
	CBCRYPT_RETURN(hash.Finish());
	std::copy_n(hash.m_HashData.cbegin(), std::min(size_t(cbOutput), hash.m_HashData.size()), pbOutput);
};
