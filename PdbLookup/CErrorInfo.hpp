#pragma once
#include <Objbase.h>
#include <comutil.h>

#include <new>

class CErrorInfo : public IErrorInfo
{
	GUID m_GUID;
	_bstr_t m_Description;
	ULONG volatile m_RefCnt = 0;
	CErrorInfo(LPCWSTR desc)
		: m_Description(desc)
	{
		::CoCreateGuid(&m_GUID);
	}
public:
	static CErrorInfo* Create(LPCWSTR desc)
	{
		return new(std::nothrow) CErrorInfo{ desc };
	}

	virtual HRESULT STDMETHODCALLTYPE QueryInterface(
		/* [in] */ REFIID riid,
		/* [iid_is][out] */ _COM_Outptr_ void __RPC_FAR *__RPC_FAR *ppvObject)
	{
		if (riid == __uuidof(IErrorInfo))
		{
			*ppvObject = (IErrorInfo*)this;
			return S_OK;
		}
		return E_NOINTERFACE;
	}

	virtual ULONG STDMETHODCALLTYPE AddRef(void)
	{
		return ::InterlockedIncrement(&m_RefCnt);
	}

	virtual ULONG STDMETHODCALLTYPE Release(void)
	{
		auto cnt = ::InterlockedDecrement(&m_RefCnt);
		if (cnt == 0)
		{
			delete this;
		}
		return cnt;
	}

	virtual HRESULT STDMETHODCALLTYPE GetGUID(
		/* [out] */ __RPC__out GUID *pGUID)
	{
		*pGUID = m_GUID;
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE GetSource(
		/* [out] */ __RPC__deref_out_opt BSTR *)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE GetDescription(
		/* [out] */ __RPC__deref_out_opt BSTR *pBstrDescription)
	{
		*pBstrDescription = m_Description;
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE GetHelpFile(
		/* [out] */ __RPC__deref_out_opt BSTR *)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE GetHelpContext(
		/* [out] */ __RPC__out DWORD *)
	{
		return E_NOTIMPL;
	}
};
