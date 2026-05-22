#ifndef HOOK_MANAGER_H
#define HOOK_MANAGER_H

#include <windows.h>

// Forward declarations — keeps wbemidl.h out of consumers of this header.
struct IEnumWbemClassObject;
struct IWbemClassObject;
struct IWbemServices;

bool InitializeHooks();
void CleanupHooks();

bool InitializeRegistryHooks();
bool InitializeFileHooks();
bool InitializeDeviceHooks();
bool InitializeProcessHooks();
bool InitializeWndHooks();
bool InitializeNetworkHooks();
bool InitializeMacAddresHooks();
bool InitializeFirmwareTableHooks();
bool InitializeHyperVObjHooks();
bool InitializeSystemHooks();
bool InitializePowerHooks();
bool InitializeServicesHooks();

// ---------------------------------------------------------------------------
// WMI — IEnumWbemClassObject::Next hooks (separate function-body patches).
// ---------------------------------------------------------------------------
bool InitializeWmiNextHook(IEnumWbemClassObject* pEnum);
bool InitializeWmiFilterPnPHook(IEnumWbemClassObject* pEnum);
void CleanupWmiNextHook();
void CleanupWmiFilterPnPHook();

// ---------------------------------------------------------------------------
// WMI — IWbemClassObject::Get hooks.
//
// All Get-class hooks share a single MinHook detour (Hook_DispatcherGet)
// because every IWbemClassObject in ROOT\CIMV2 resolves Get to the same
// function body — only one MinHook patch can exist on that address.
// Each Install*Hook installs the dispatcher (idempotent) and enables its
// per-class flag; Remove*Hook clears its flag and removes the dispatcher
// when all class flags are off.  All Install/Remove functions need a seed
// IWbemClassObject* on first call to locate the vtable.
// ---------------------------------------------------------------------------
bool InstallBaseBoardHook(IWbemClassObject* pObj);
bool InstallBusHook(IWbemClassObject* pObj);
bool InstallPnPDeviceHook(IWbemClassObject* pObj);
bool InstallBiosHook(IWbemClassObject* pObj);
bool InstallComputerSystemHook(IWbemClassObject* pObj);
bool InstallVideoHook(IWbemClassObject* pObj);
bool InstallProcessorHook(IWbemClassObject* pObj);
bool InstallLogicalDiskHook(IWbemClassObject* pObj);
bool InstallThermalHook(IWbemClassObject* pObj);
bool InstallEventLogHook(IWbemClassObject* pObj);

void RemoveBaseBoardHook();
void RemoveBusHook();
void RemovePnPDeviceHook();
void RemoveBiosHook();
void RemoveComputerSystemHook();
void RemoveVideoHook();
void RemoveProcessorHook();
void RemoveLogicalDiskHook();
void RemoveThermalHook();
void RemoveEventLogHook();

// Installs the shared Get-dispatcher and enables all six class spoofs.
bool InstallAllHooks(IWbemClassObject* pObj);

// Clears every class flag and tears down the Get-dispatcher.
void RemoveAllHooks();

// ---------------------------------------------------------------------------
// IWbemServices::ExecQuery patch + non-empty injection master switch.
// One MinHook patch on the ExecQuery function body — the detour tags any
// enumerator whose WQL targets a critical class so that the existing
// Next detour can fabricate one synthetic IWbemClassObject when the real
// enumerator turns up empty.  Needs a live IWbemServices for the vtable
// seed.
// ---------------------------------------------------------------------------
bool InstallExecQueryHook(IWbemServices* pSvc);
void RemoveExecQueryHook();

// Self-contained WMI hook bootstrap.  Initialises COM, opens ROOT\CIMV2,
// obtains seed enumerator + seed object, then installs the FilterPnP
// Next hook AND the Get dispatcher with all six class spoofs enabled.
// Call once from DllMain (DLL_PROCESS_ATTACH).
bool InstallWmiHooks();

#endif // HOOK_MANAGER_H
