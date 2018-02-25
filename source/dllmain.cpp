#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "Hooking.Patterns.h"
#include "injector\injector.hpp"

HWND __stdcall CreateWindowExWProxy(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
    dwStyle |= WS_POPUP;
    dwStyle &= ~(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_THICKFRAME | WS_MAXIMIZEBOX);
    return CreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

HWND __stdcall CreateWindowExAProxy(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
    dwStyle |= WS_POPUP;
    dwStyle &= ~(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_THICKFRAME | WS_MAXIMIZEBOX);
    return CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

DWORD WINAPI Init(LPVOID bDelay)
{
    auto pattern = hook::module_pattern(GetModuleHandle("engine_x64_rwdi"), "FF 15 ? ? ? ? 48 8B F0 48 89 44 24 ? 8B FB 48 85 C0 40 0F 94 C7");

    if (pattern.count_hint(4).empty() && !bDelay)
    {
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Init, (LPVOID)true, 0, NULL);
        return 0;
    }

    if (bDelay)
        while (pattern.clear(GetModuleHandle("engine_x64_rwdi")).count_hint(4).empty()) { Sleep(0); };

    injector::MakeNOP(pattern.count(4).get(1).get<void>(0), 6, true);
    injector::MakeCALL(pattern.count(4).get(1).get<void>(0), CreateWindowExAProxy, true);
    injector::MakeNOP(pattern.count(4).get(2).get<void>(0), 6, true);
    injector::MakeCALL(pattern.count(4).get(2).get<void>(0), CreateWindowExWProxy, true);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD reason, LPVOID /*lpReserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        Init(NULL);
    }
    return TRUE;
}