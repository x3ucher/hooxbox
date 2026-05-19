#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wbemidl.h>
#include <string>

namespace WmiHooks {
    // Appends a UTF-8 log entry to sandbox_evasion.log in the process working dir.
    // Thread-safe.
    void Log(const wchar_t* level, const std::wstring& msg);
}

#define WMIHOOK_INFO(msg)  WmiHooks::Log(L"INFO",  (msg))
#define WMIHOOK_WARN(msg)  WmiHooks::Log(L"WARN",  (msg))
#define WMIHOOK_ERROR(msg) WmiHooks::Log(L"ERROR", (msg))

// Installs a MinHook detour on IEnumWbemClassObject::Next (vtable slot 4).
// The hook calls the original Next, then logs the return count via WMIHOOK_INFO.
// The hook applies to all enumerators sharing the same vtable.
// Returns false if pEnum is null or any MinHook call fails.
bool HookEnumeratorNext(IEnumWbemClassObject* pEnum);

// Removes the hook installed by HookEnumeratorNext and uninitialises MinHook.
void UnhookEnumeratorNext();

// Installs a filtering detour on IEnumWbemClassObject::Next (vtable slot 4).
// After each original Next call, inspects the Name property of every returned
// object. Objects whose Name contains any of the VM-indicator substrings
// ("82801FB", "82441FX", "82371SB", "OpenHCD", "VBOX") are released and
// removed from the output array. The hook retries internally until at least
// one unfiltered object is available or the enumerator is exhausted, so the
// caller's loop terminates correctly even when all objects are filtered.
// Returns false if pEnum is null or any MinHook call fails.
bool HookEnumeratorNext_FilterPnPName(IEnumWbemClassObject* pEnum);

// Removes the hook installed by HookEnumeratorNext_FilterPnPName.
void UnhookEnumeratorNext_FilterPnPName();

// Installs a MinHook detour on IWbemClassObject::Get (vtable slot 4).
// The detour intercepts Get calls for the "Product" and "Manufacturer"
// properties and returns spoofed values only when the object's __CLASS is
// "Win32_BaseBoard"; all other properties and all other classes pass through
// to the original Get unchanged.
// pObj must be a live Win32_BaseBoard IWbemClassObject (used to locate the
// function address from the vtable; the hook survives its release).
// Returns false if pObj is null or any MinHook call fails.
bool HookBaseBoardGet(IWbemClassObject* pObj);

// Removes the hook installed by HookBaseBoardGet and uninitialises MinHook.
void UnhookBaseBoardGet();

// Installs a MinHook detour on IWbemClassObject::Get (vtable slot 4) for
// Win32_Bus objects.  When the "Name" property is requested, the hook
// replaces the known VirtualBox bus names with neutral variants:
//   ACPIBus_BUS_0 -> ACPIBus_BUS_1
//   PCI_BUS_0     -> PCI_BUS_1
//   PNP_BUS_0     -> PNP_BUS_1
// This breaks the detection condition (count==3 && findCount==3).
// pObj must be a live Win32_Bus IWbemClassObject used to locate Get from
// the vtable; the hook survives its release.
bool HookBusGet(IWbemClassObject* pObj);

// Removes the hook installed by HookBusGet and uninitialises MinHook.
void UnhookBusGet();

// Installs a MinHook detour on IWbemClassObject::Get (vtable slot 4) for
// Win32_PnPDevice objects.  For the Name, Caption, and PNPDeviceID properties,
// all occurrences of "VEN_VBOX" are replaced with "VEN_GENERIC" and all
// occurrences of "VBOX" are replaced with "Generic".  All other properties
// and all other classes pass through to the original Get unchanged.
bool HookPnPDeviceGet(IWbemClassObject* pObj);

// Removes the hook installed by HookPnPDeviceGet and uninitialises MinHook.
void UnhookPnPDeviceGet();
