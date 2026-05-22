#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wbemidl.h>
#include <string>

#include "log_utils.h"

// File-logger macros used inside the WMI detours.
#define WMIHOOK_INFO(msg)  WriteFileLog(L"INFO",  (msg))
#define WMIHOOK_WARN(msg)  WriteFileLog(L"WARN",  (msg))
#define WMIHOOK_ERROR(msg) WriteFileLog(L"ERROR", (msg))

// ---------------------------------------------------------------------------
// IEnumWbemClassObject vtable: [4] Next.
// IWbemClassObject   vtable: [4] Get.
// ---------------------------------------------------------------------------
namespace WmiMaskHooks {

constexpr int kVtblSlot_Next      = 4;
constexpr int kVtblSlot_WbemGet   = 4;
constexpr int kVtblSlot_ExecQuery = 20;   // IWbemServices::ExecQuery

typedef HRESULT (STDMETHODCALLTYPE *FnNext)(
    IEnumWbemClassObject* pThis,
    LONG                  lTimeout,
    ULONG                 uCount,
    IWbemClassObject**    apObjects,
    ULONG*                puReturned);

typedef HRESULT (STDMETHODCALLTYPE *FnWbemGet)(
    IWbemClassObject* pThis,
    LPCWSTR           wszName,
    LONG              lFlags,
    VARIANT*          pVal,
    CIMTYPE*          pType,
    LONG*             plFlavor);

typedef HRESULT (STDMETHODCALLTYPE *FnExecQuery)(
    IWbemServices*         pThis,
    BSTR                   strQueryLanguage,
    BSTR                   strQuery,
    LONG                   lFlags,
    IWbemContext*          pCtx,
    IEnumWbemClassObject** ppEnum);

// Original-function pointers.  Populated by hook_manager on install,
// read by the detours below.  All IWbemClassObject Get-detours share a
// single trampoline because the WMI proxies use one common vtable for
// every class in ROOT\CIMV2 — so MinHook can only patch Get at one
// address, and per-class behaviour is multiplexed by Hook_DispatcherGet
// using the enable flags below.
extern FnNext       g_pOrigNext;
extern FnNext       g_pOrigNextFilter;
extern FnWbemGet    g_pOrigGet;
extern FnExecQuery  g_pOrigExecQuery;

// Per-class spoofing flags.  Set/cleared by the corresponding
// Install*Hook / Remove*Hook functions in hook_manager; the dispatcher
// reads them on every Get call.
extern bool g_BaseBoardEnabled;
extern bool g_BusEnabled;
extern bool g_PnPDeviceEnabled;
extern bool g_BiosEnabled;
extern bool g_ComputerSystemEnabled;
extern bool g_VideoEnabled;
extern bool g_ProcessorEnabled;
extern bool g_LogicalDiskEnabled;
extern bool g_ThermalEnabled;
extern bool g_EventLogEnabled;

// Non-empty injection master switch.  When true and ExecQuery returned
// an enumerator whose target class is in the critical list, the first
// Next that would yield 0 objects instead gets a synthetic
// IWbemClassObject — defeats "class is empty == VM" sandbox probes.
extern bool g_NonEmptyEnabled;

// Detours.
HRESULT STDMETHODCALLTYPE Hook_Next(
    IEnumWbemClassObject* pThis, LONG lTimeout, ULONG uCount,
    IWbemClassObject** apObjects, ULONG* puReturned);

HRESULT STDMETHODCALLTYPE Hook_Next_FilterPnP(
    IEnumWbemClassObject* pThis, LONG lTimeout, ULONG uCount,
    IWbemClassObject** apObjects, ULONG* puReturned);

// Single Get-detour shared by all per-class hooks.  Dispatches on
// IWbemClassObject::__CLASS and the per-class enable flags.
HRESULT STDMETHODCALLTYPE Hook_DispatcherGet(
    IWbemClassObject* pThis, LPCWSTR wszName, LONG lFlags,
    VARIANT* pVal, CIMTYPE* pType, LONG* plFlavor);

// Tags every IEnumWbemClassObject returned for a critical-class WQL
// query so that the Next detour can supply a fake row on empty results.
HRESULT STDMETHODCALLTYPE Hook_ExecQuery(
    IWbemServices* pThis, BSTR strQueryLanguage, BSTR strQuery,
    LONG lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum);

} // namespace WmiMaskHooks
