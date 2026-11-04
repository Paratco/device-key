/**
 * win_delay_load_hook.cpp
 *
 * Redirect all Windows delay-loaded DLL requests for N-API symbols to the
 * current host process module (node.exe, bun.exe, electron.exe, …).
 *
 * How it works
 * ─────────────
 * The N-API import library (napi.lib / node.lib) tells the linker that the
 * napi_* symbols come from NODE.EXE.  Combined with /DELAYLOAD:NODE.EXE the
 * linker generates delay-load stubs: the symbols are NOT resolved at load time
 * but on first call.  That first call triggers the Windows delay-load support
 * library which fires __pfnDliNotifyHook2 (dliNotePreLoadLibrary) before it
 * tries to LoadLibrary("NODE.EXE").  We intercept that event and return a
 * handle to the current process (GetModuleHandle(NULL)).  The host process
 * (bun.exe, node.exe, …) exports all napi_ symbols, so GetProcAddress
 * succeeds and the addon works regardless of which runtime loaded it.
 *
 * This mirrors the technique used by both cmake-js and node-gyp.
 */

#ifdef _WIN32

#pragma comment(lib, "delayimp.lib")

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <delayimp.h>

static FARPROC WINAPI napi_delay_load_hook(unsigned int event, DelayLoadInfo* /* info */) {
    if (event != dliNotePreLoadLibrary) {
        return nullptr;
    }
    return reinterpret_cast<FARPROC>(::GetModuleHandle(nullptr));
}

// Register as the notification hook.  The failure hook is intentionally not
// overridden so that a genuine load failure still surfaces an error.
decltype(__pfnDliNotifyHook2) __pfnDliNotifyHook2 = napi_delay_load_hook;

#endif // _WIN32

