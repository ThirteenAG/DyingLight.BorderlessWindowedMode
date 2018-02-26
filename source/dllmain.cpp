#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tuple>
#include "Hooking.Patterns.h"
#include "injector\injector.hpp"

struct Screen
{
    int32_t nWidth;
    int32_t nHeight;
    bool bBorderless = true;
    uintptr_t qword_180A29C08;
} Screen;

std::tuple<int32_t, int32_t> GetDesktopRes()
{
    HMONITOR monitor = MonitorFromWindow(GetDesktopWindow(), MONITOR_DEFAULTTONEAREST);
    MONITORINFO info = {};
    info.cbSize = sizeof(MONITORINFO);
    GetMonitorInfo(monitor, &info);
    int32_t DesktopResW = info.rcMonitor.right - info.rcMonitor.left;
    int32_t DesktopResH = info.rcMonitor.bottom - info.rcMonitor.top;
    return std::make_tuple(DesktopResW, DesktopResH);
}

LRESULT __stdcall DefWindowProcAProxy(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    switch (Msg)
    {
    case WM_SIZE:
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
        if (Msg == WM_SYSKEYDOWN && wParam == VK_RETURN && (HIWORD(lParam) & KF_ALTDOWN))
            Screen.bBorderless = !Screen.bBorderless;

        if (Screen.bBorderless)
            SetWindowLong(hWnd, GWL_STYLE, GetWindowLong(hWnd, GWL_STYLE) & ~WS_OVERLAPPEDWINDOW);
        else
            SetWindowLong(hWnd, GWL_STYLE, GetWindowLong(hWnd, GWL_STYLE) | WS_OVERLAPPEDWINDOW);

        auto[DesktopResW, DesktopResH] = GetDesktopRes();
        auto ptr = *(uintptr_t*)(*(uintptr_t*)Screen.qword_180A29C08 + 0xC0);
        Screen.nWidth = *(int32_t*)(ptr + 0x10);
        Screen.nHeight = *(int32_t*)(ptr + 0x14);

        RECT Rect{
            (LONG)(((float)DesktopResW / 2.0f) - ((float)Screen.nWidth / 2.0f)),
            (LONG)(((float)DesktopResH / 2.0f) - ((float)Screen.nHeight / 2.0f)),
            (LONG)Screen.nWidth,
            (LONG)Screen.nHeight
        };
        AdjustWindowRectEx(&Rect, GetWindowLong(hWnd, GWL_STYLE), NULL, GetWindowLong(hWnd, GWL_EXSTYLE));
        SetWindowPos(hWnd, HWND_TOP, Rect.left, Rect.top, Rect.right, Rect.bottom, SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
        break;
    }
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

DWORD WINAPI Init(LPVOID bDelay)
{
    auto pattern = hook::module_pattern(GetModuleHandle("engine_x64_rwdi"), "48 8B 05 ? ? ? ? 33 FF 48 8B 88 ? ? ? ? 48 89 7D F7 8D 57 F0 8B 41 10");

    if (pattern.count_hint(1).empty() && !bDelay)
    {
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Init, (LPVOID)true, 0, NULL);
        return 0;
    }

    if (bDelay)
        while (pattern.clear(GetModuleHandle("engine_x64_rwdi")).count_hint(1).empty()) { Sleep(0); };

    Screen.qword_180A29C08 = injector::GetAbsoluteOffset(*pattern.get_first<uint32_t>(3), pattern.get_first(7)).as_int();
    pattern = hook::module_pattern(GetModuleHandle("engine_x64_rwdi"), "FF 15 ? ? ? ? 4C 8D 9C 24 ? ? ? ? 49 8B 5B 30 49 8B 73 40 49 8B 7B 48 49 8B E3 41 5F 41 5E 41 5D 41 5C 5D C3");
    injector::MakeNOP(pattern.get_first(), 6, true);
    injector::MakeCALL(pattern.get_first(), DefWindowProcAProxy, true);

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