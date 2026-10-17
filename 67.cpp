// ============================================================================
//  67 - Roblox External Executor
//  Un solo archivo. C++17 / Win32 / x64. Sin dependencias externas.
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <uxtheme.h>
#include <commctrl.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' "\
                        "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using u8  = uint8_t;  using u16 = uint16_t;
using u32 = uint32_t; using u64 = uint64_t;

namespace cfg {
    const wchar_t* kTarget = L"RobloxPlayerBeta.exe";
    const wchar_t* kTitle  = L"67  |  roblox external executor";
    const wchar_t* kIni    = L"67.ini";
}

// ================================ LOG ======================================
static std::wstring       g_log;
static std::mutex         g_logMx;
static HWND               g_hwnd = nullptr;
static HWND               g_edit = nullptr;
static HWND               g_logBox = nullptr;
static HWND               g_status = nullptr;
static HFONT              g_fontUI = nullptr;
static HFONT              g_fontMono = nullptr;

#define WM_APP_LOG (WM_APP + 1)

static void Log(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t line[1200];
    _snwprintf_s(line, _countof(line), _TRUNCATE, L"[%02d:%02d:%02d] %s\r\n",
                 st.wHour, st.wMinute, st.wSecond, buf);
    { std::lock_guard<std::mutex> lk(g_logMx); g_log += line; }
    if (g_hwnd) PostMessageW(g_hwnd, WM_APP_LOG, 0, 0);
}

// ============================ UTILIDADES ===================================
static bool plausiblePtr(u64 p) {
    return p > 0x10000 && p < 0x00007FFFFFFFFFFFULL && (p & 7) == 0;
}

static void EnableDebugPrivilege() {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp{}; tp.PrivilegeCount = 1;
    LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(tok);
}

static DWORD FindPid(const wchar_t* exe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// ============================== PROCESO ====================================
namespace mem {

class Process {
public:
    HANDLE h = nullptr;
    DWORD  pid = 0;
    u64    base = 0;
    u64    imageSize = 0;
    u64    textBase = 0;
    u64    textSize = 0;
    u64    scratch = 0;

    bool attach(const wchar_t* exe) {
        detach();
        pid = FindPid(exe);
        if (!pid) return false;

        const DWORD want = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                           PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
        h = OpenProcess(want, FALSE, pid);
        if (!h) h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!h) { Log(L"OpenProcess fallo (err %lu)", GetLastError()); return false; }

        if (!resolveModule(exe)) { Log(L"no se pudo leer el modulo base"); detach(); return false; }

        scratch = alloc(0x2000);
        if (!scratch) { Log(L"VirtualAllocEx fallo"); detach(); return false; }

        Log(L"adjuntado a %s  pid=%lu  base=%p  .text=%p (%llu KB)",
            exe, pid, (void*)base, (void*)textBase, textSize / 1024);
        return true;
    }

    void detach() {
        if (h && scratch) VirtualFreeEx(h, (LPVOID)scratch, 0, MEM_RELEASE);
        scratch = 0; base = textBase = textSize = imageSize = 0;
        if (h) CloseHandle(h);
        h = nullptr; pid = 0;
    }

    bool ok() const { return h != nullptr; }

    template <class T> T read(u64 a) const {
        T v{};
        if (h) ReadProcessMemory(h, (LPCVOID)a, &v, sizeof(T), nullptr);
        return v;
    }
    template <class T> bool write(u64 a, const T& v) const {
        return h && WriteProcessMemory(h, (LPVOID)a, &v, sizeof(T), nullptr);
    }
    bool readBytes(u64 a, void* out, size_t n) const {
        SIZE_T got = 0;
        return h && ReadProcessMemory(h, (LPCVOID)a, out, n, &got) && got == n;
    }
    std::vector<u8> readBytes(u64 a, size_t n) const {
        std::vector<u8> b(n, 0);
        readBytes(a, b.data(), n);
        return b;
    }
    bool writeBytes(u64 a, const void* d, size_t n) const {
        SIZE_T put = 0;
        return h && WriteProcessMemory(h, (LPVOID)a, d, n, &put) && put == n;
    }
    u64 alloc(size_t n, DWORD prot = PAGE_EXECUTE_READWRITE) const {
        return h ? (u64)VirtualAllocEx(h, nullptr, n, MEM_COMMIT | MEM_RESERVE, prot) : 0;
    }
    bool freeMem(u64 a) const { return h && VirtualFreeEx(h, (LPVOID)a, 0, MEM_RELEASE); }

    u64 call(u64 fn, u64 a1 = 0, u64 a2 = 0, u64 a3 = 0,
             u64 a4 = 0, u64 a5 = 0, u64 a6 = 0, DWORD timeoutMs = 10000) const {
        if (!ok() || !scratch || !fn) return 0;

        const u64 stubAddr = scratch;
        const u64 retSlot  = scratch + 0x1000;

        std::vector<u8> c;
        auto imm64 = [&](u8 rex, u8 op, u64 v) {
            c.push_back(rex); c.push_back(op);
            for (int i = 0; i < 8; ++i) c.push_back((u8)(v >> (8 * i)));
        };
        auto raw = [&](std::initializer_list<u8> b) { c.insert(c.end(), b); };

        raw({0x48, 0x83, 0xEC, 0x38});                               // sub rsp, 0x38
        imm64(0x49, 0xBB, a5); raw({0x4C, 0x89, 0x5C, 0x24, 0x20});  // mov [rsp+0x20], r11
        imm64(0x49, 0xBB, a6); raw({0x4C, 0x89, 0x5C, 0x24, 0x28});  // mov [rsp+0x28], r11
        imm64(0x48, 0xB8, fn);                                       // mov rax, fn
        imm64(0x48, 0xB9, a1);                                       // mov rcx, a1
        imm64(0x48, 0xBA, a2);                                       // mov rdx, a2
        imm64(0x49, 0xB8, a3);                                       // mov r8,  a3
        imm64(0x49, 0xB9, a4);                                       // mov r9,  a4
        raw({0xFF, 0xD0});                                           // call rax
        raw({0x48, 0x83, 0xC4, 0x38});                               // add rsp, 0x38
        imm64(0x49, 0xBB, retSlot);                                  // mov r11, retSlot
        raw({0x49, 0x89, 0x03});                                     // mov [r11], rax
        raw({0xC3});                                                 // ret

        write<u64>(retSlot, 0);
        writeBytes(stubAddr, c.data(), c.size());

        HANDLE t = CreateRemoteThread(h, nullptr, 0, (LPTHREAD_START_ROUTINE)stubAddr, nullptr, 0, nullptr);
        if (!t) { Log(L"CreateRemoteThread fallo (err %lu)", GetLastError()); return 0; }
        DWORD w = WaitForSingleObject(t, timeoutMs);
        if (w == WAIT_TIMEOUT) { Log(L"timeout en llamada remota a %p", (void*)fn); TerminateThread(t, 0); }
        CloseHandle(t);
        return read<u64>(retSlot);
    }

private:
    bool resolveModule(const wchar_t* exe) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return false;
        MODULEENTRY32W me{}; me.dwSize = sizeof(me);
        bool found = false;
        if (Module32FirstW(snap, &me)) {
            do {
                if (_wcsicmp(me.szModule, exe) == 0) {
                    base = (u64)me.modBaseAddr; imageSize = me.modBaseSize; found = true; break;
                }
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        if (!found) return false;

        auto dos = readBytes(base, 0x400);
        if (dos.size() < 0x40 || dos[0] != 'M' || dos[1] != 'Z') return false;
        u32 peOff = *(u32*)(dos.data() + 0x3C);
        auto pe = readBytes(base + peOff, 0x200);
        if (pe.size() < 0x40 || pe[0] != 'P' || pe[1] != 'E') return false;
        u16 nsec = *(u16*)(pe.data() + 0x06);
        u16 optSize = *(u16*)(pe.data() + 0x14);
        u64 secOff = peOff + 0x18 + optSize;

        for (u16 i = 0; i < nsec; ++i) {
            auto s = readBytes(base + secOff + i * 40ULL, 40);
            if (s.size() < 40) break;
            if (memcmp(s.data(), ".text", 5) == 0) {
                textBase = base + *(u32*)(s.data() + 12);
                textSize = *(u32*)(s.data() + 8);
                return true;
            }
        }
        return false;
    }
};

} // namespace mem

// ============================== SCANNER ====================================
class Scanner {
public:
    explicit Scanner(const mem::Process& p) : P(p) {}

    u64 find(const char* sig, u64 start, u64 len, int skip = 0) const {
        std::vector<int> pat; std::vector<u8> mask;
        if (!parse(sig, pat, mask)) return 0;
        auto data = P.readBytes(start, (size_t)len);
        if (data.size() != len) return 0;
        int hits = 0;
        for (size_t i = 0; i + pat.size() <= data.size(); ++i) {
            bool ok = true;
            for (size_t j = 0; j < pat.size(); ++j)
                if (mask[j] && data[i + j] != (u8)pat[j]) { ok = false; break; }
            if (ok && hits++ == skip) return start + i;
        }
        return 0;
    }
    u64 findText(const char* sig, int skip = 0) const {
        return find(sig, P.textBase, P.textSize, skip);
    }
    u64 resolveRip(u64 instr, int dispOff = 3, int instrLen = 7) const {
        int32_t rel = P.read<int32_t>(instr + dispOff);
        return instr + instrLen + rel;
    }
    u64 functionStart(u64 anchor) const {
        const u64 back = 0x900;
        u64 start = (anchor > back && anchor - back > P.textBase) ? anchor - back : P.textBase;
        auto b = P.readBytes(start, (size_t)(anchor - start + 8));
        int last = -1;
        for (int i = 0; i + 4 <= (int)b.size(); ++i)
            if (b[i] == 0xCC && b[i+1] == 0xCC && b[i+2] == 0xCC && b[i+3] == 0xCC) last = i;
        if (last < 0) return 0;
        u64 p = start + last;
        while (P.read<u8>(p) == 0xCC) ++p;
        return p;
    }
private:
    const mem::Process& P;
    static bool parse(const char* sig, std::vector<int>& pat, std::vector<u8>& mask) {
        for (const char* p = sig; *p; ) {
            while (*p == ' ') ++p;
            if (!*p) break;
            if (p[0] == '?' && p[1] == '?') { pat.push_back(0); mask.push_back(0); p += 2; }
            else {
                char* end = nullptr;
                long v = strtol(p, &end, 16);
                if (end == p) return false;
                pat.push_back((int)v); mask.push_back(1); p = end;
            }
        }
        return !pat.empty();
    }
};

// ============================== ROBLOX =====================================
static const char* SIG_DATAMODEL[] = {
    "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 74",
};
static const char* SIG_LUA_PCALL[] = {
    "48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 55 48 8D 68 A8",
    "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20",
    "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24",
};
static const char* SIG_LUA_TOLSTRING[] = {
    "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 8B F9 48 63 CA",
};
static const char* SIG_LUA_SETTOP[] = {
    "48 63 D2 85 D2 7E",
    "85 D2 78 ?? 48 63 C2 48 8B 89",
};
static const char* SIG_ANCHOR_LUA_LOAD = "1B 4C 75 61";

class Roblox {
public:
    mem::Process proc;
    u64 dataModel = 0, scriptContext = 0, luaState = 0;
    u64 fnLoad = 0, fnPcall = 0, fnTolstring = 0, fnSettop = 0;
    bool ready = false;

    bool attach() {
        ready = false;
        dataModel = scriptContext = luaState = 0;
        fnLoad = fnPcall = fnTolstring = fnSettop = 0;
        if (!proc.attach(cfg::kTarget)) { Log(L"Roblox no esta abierto."); return false; }

        Scanner sc(proc);

        u64 p = sc.findText(SIG_DATAMODEL[0]);
        if (!p) { Log(L"[!] firma DataModel no encontrada"); return false; }
        u64 fakeGlobal = sc.resolveRip(p, 3, 7);
        u64 fake = proc.read<u64>(fakeGlobal);
        int32_t dmOff = proc.read<int32_t>(p + 10);
        dataModel = proc.read<u64>(fake + dmOff);
        if (!plausiblePtr(dataModel)) { Log(L"[!] DataModel invalido (%p)", (void*)dataModel); return false; }
        Log(L"DataModel @ %p", (void*)dataModel);

        if (!locateLuaState()) { Log(L"[!] no se encontro el lua_State"); return false; }
        Log(L"lua_State @ %p", (void*)luaState);

        resolveFunctions();
        if (!fnLoad || !fnPcall) { Log(L"[!] faltan luau_load / lua_pcall"); return false; }

        if (!selfTest()) { Log(L"[!] el self-test fallo"); return false; }

        ready = true;
        Log(L"** 67 listo. **");
        return true;
    }

    void detach() { proc.detach(); ready = false; }

    bool run(const std::string& src) {
        if (!ready) { Log(L"no adjuntado"); return false; }
        if (src.empty()) return true;

        u64 bufSrc  = proc.alloc(src.size() + 16);
        u64 bufName = proc.alloc(16);
        u64 bufLen  = proc.alloc(8);
        u64 bufMsg  = proc.alloc(4096);
        if (!bufSrc || !bufName) { Log(L"sin memoria en el target"); return false; }

        proc.writeBytes(bufSrc, src.data(), src.size());
        proc.writeBytes(bufName, "=67", 4);
        proc.write<u64>(bufLen, 0);

        u64 st = proc.call(fnLoad, luaState, bufName, bufSrc, (u64)src.size(), 0);
        if (st != 0) {
            std::string msg = readError(bufMsg, bufLen);
            Log(L"[sintaxis] %S", msg.c_str());
            if (fnSettop) proc.call(fnSettop, luaState, (u64)-2);
            cleanup(bufSrc, bufName, bufLen, bufMsg);
            return false;
        }

        u64 rc = proc.call(fnPcall, luaState, 0, 0, 0, 0, 0, 60000);
        if (rc >= 2) {
            std::string msg = readError(bufMsg, bufLen);
            Log(L"[error] %S", msg.c_str());
            if (fnSettop) proc.call(fnSettop, luaState, (u64)-2);
            cleanup(bufSrc, bufName, bufLen, bufMsg);
            return false;
        }
        if (rc == 1) Log(L"[ok] script ejecutado (cedio el hilo; sigue en el scheduler)");
        else         Log(L"[ok] script ejecutado");
        cleanup(bufSrc, bufName, bufLen, bufMsg);
        return true;
    }

private:
    void cleanup(u64 a, u64 b, u64 c, u64 d) {
        proc.freeMem(a); proc.freeMem(b); proc.freeMem(c); proc.freeMem(d);
    }

    std::string readError(u64 bufMsg, u64 bufLen) {
        (void)bufMsg;
        std::string msg = "(sin mensaje)";
        if (!fnTolstring) return msg;
        u64 pStr = proc.call(fnTolstring, luaState, (u64)-1, bufLen);
        u64 len  = proc.read<u64>(bufLen);
        if (pStr && len) {
            len = std::min<u64>(len, 4000);
            auto b = proc.readBytes(pStr, (size_t)len);
            msg.assign((const char*)b.data(), (size_t)len);
        }
        return msg;
    }

    bool isLuaState(u64 p) const {
        if (!plausiblePtr(p)) return false;
        return proc.read<u8>(p + 8) == 9;
    }

    bool locateLuaState() {
        const u64 SPAN = 0x3000;
        auto buf = proc.readBytes(dataModel, SPAN);
        if (buf.size() != SPAN) return false;

        int budget = 500;
        for (u64 off = 0; off + 8 <= SPAN; off += 8) {
            u64 cand = *(u64*)(buf.data() + off);
            if (!plausiblePtr(cand)) continue;

            u64 vt = proc.read<u64>(cand);
            if (vt < proc.base || vt > proc.base + proc.imageSize) continue;
            if (--budget <= 0) break;

            auto ob = proc.readBytes(cand, 0x800);
            if (ob.size() != 0x800) continue;
            for (u64 o2 = 0; o2 + 8 <= 0x800; o2 += 8) {
                u64 st = *(u64*)(ob.data() + o2);
                if (isLuaState(st)) {
                    scriptContext = cand;
                    luaState = st;
                    Log(L"ScriptContext @ %p (off DataModel+0x%llX, state+0x%llX)",
                        (void*)cand, off, o2);
                    return true;
                }
            }
        }
        return false;
    }

    void resolveFunctions() {
        Scanner sc(proc);
        auto first = [&](const char** list, size_t n) -> u64 {
            for (size_t i = 0; i < n; ++i) { u64 a = sc.findText(list[i]); if (a) return a; }
            return 0;
        };
        fnPcall     = first(SIG_LUA_PCALL,     _countof(SIG_LUA_PCALL));
        fnTolstring = first(SIG_LUA_TOLSTRING, _countof(SIG_LUA_TOLSTRING));
        fnSettop    = first(SIG_LUA_SETTOP,    _countof(SIG_LUA_SETTOP));

        u64 anchor = sc.findText(SIG_ANCHOR_LUA_LOAD);
        if (anchor) fnLoad = sc.functionStart(anchor);

        fnLoad      = iniRva(L"luau_load",     fnLoad);
        fnPcall     = iniRva(L"lua_pcall",     fnPcall);
        fnTolstring = iniRva(L"lua_tolstring", fnTolstring);
        fnSettop    = iniRva(L"lua_settop",    fnSettop);

        Log(L"luau_load=%p lua_pcall=%p lua_tolstring=%p lua_settop=%p",
            (void*)fnLoad, (void*)fnPcall, (void*)fnTolstring, (void*)fnSettop);
    }

    u64 iniRva(const wchar_t* key, u64 fallback) {
        wchar_t buf[64]{};
        GetPrivateProfileStringW(L"rva", key, L"", buf, 64, cfg::kIni);
        if (!buf[0]) return fallback;
        u64 rva = wcstoull(buf, nullptr, 16);
        if (!rva) return fallback;
        Log(L"rva override %s = 0x%llX", key, rva);
        return proc.base + rva;
    }

    bool selfTest() {
        const char* code =
            "if type(selftest67) ~= 'table' then selftest67 = {} end "
            "selftest67.n = (selftest67.n or 0) + 1 "
            "return selftest67.n";
        u64 a = proc.alloc(256), b = proc.alloc(16);
        if (!a || !b) return false;
        proc.writeBytes(a, code, strlen(code));
        proc.writeBytes(b, "=67selftest", 12);
        u64 st = proc.call(fnLoad, luaState, b, a, (u64)strlen(code), 0);
        bool ok = (st == 0);
        if (ok) {
            u64 rc = proc.call(fnPcall, luaState, 0, 1, 0);
            ok = (rc == 0 || rc == 1);
            if (fnSettop) proc.call(fnSettop, luaState, (u64)-2);
        }
        proc.freeMem(a); proc.freeMem(b);
        Log(L"self-test: %s", ok ? L"OK" : L"FALLO");
        return ok;
    }
};

static Roblox g_rbx;

// ================================== UI =====================================
#define IDC_ATTACH 1001
#define IDC_EXEC   1002
#define IDC_CLEAR  1003
#define IDC_OPEN   1004
#define IDC_SAVE   1005
#define IDC_EDIT   1006
#define IDC_LOGBOX 1007
#define IDC_STATUS 1008

static const COLORREF C_BG     = RGB(0x14, 0x16, 0x1A);
static const COLORREF C_PANEL  = RGB(0x1B, 0x1E, 0x24);
static const COLORREF C_EDITBG = RGB(0x0F, 0x11, 0x14);
static const COLORREF C_TEXT   = RGB(0xE6, 0xE6, 0xE6);
static const COLORREF C_ACCENT = RGB(0x3D, 0xDC, 0x84);

static HBRUSH g_brBg, g_brPanel, g_brEdit;

static std::string GetEditorText() {
    int n = GetWindowTextLengthW(g_edit);
    std::wstring w(n + 1, L'\0');
    GetWindowTextW(g_edit, w.data(), n + 1);
    if (n > 0) w.resize(n);
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), len, nullptr, nullptr);
    return s;
}

static void SetEditorText(const std::string& s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), len);
    SetWindowTextW(g_edit, w.c_str());
}

static void RefreshLog() {
    std::wstring copy;
    { std::lock_guard<std::mutex> lk(g_logMx); copy = g_log; }
    if (copy.size() > 60000) copy.erase(0, copy.size() - 60000);
    SetWindowTextW(g_logBox, copy.c_str());
    SendMessageW(g_logBox, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_logBox, EM_SCROLLCARET, 0, 0);
}

static void Layout(HWND hw) {
    RECT rc; GetClientRect(hw, &rc);
    const int pad = 10, barH = 38, logH = 150;
    int w = rc.right - pad * 2;

    MoveWindow(g_status, pad, 12, w - 500, 22, TRUE);
    int bx = rc.right - pad - 92;
    int ids[] = { IDC_EXEC, IDC_ATTACH, IDC_OPEN, IDC_SAVE, IDC_CLEAR };
    for (int i = 0; i < 5; ++i) {
        HWND b = GetDlgItem(hw, ids[i]);
        MoveWindow(b, bx - (4 - i) * 96, 8, 92, 26, TRUE);
    }
    MoveWindow(g_edit, pad, barH + 12, w, rc.bottom - barH - logH - 34, TRUE);
    MoveWindow(g_logBox, pad, rc.bottom - logH - pad + 6, w, logH - 6, TRUE);
}

static void DrawBtn(DRAWITEMSTRUCT* d) {
    bool hot = (d->itemState & ODS_SELECTED) != 0;
    bool primary = (d->CtlID == IDC_EXEC);
    COLORREF bg = primary ? (hot ? RGB(0x2F, 0xB8, 0x6C) : C_ACCENT)
                          : (hot ? RGB(0x2A, 0x2F, 0x38) : C_PANEL);
    COLORREF fg = primary ? RGB(0x08, 0x10, 0x0C) : C_TEXT;

    HDC dc = d->hDC;
    RECT r = d->rcItem;
    HBRUSH b = CreateSolidBrush(bg);
    FillRect(dc, &r, b); DeleteObject(b);
    FrameRect(dc, &r, (HBRUSH)GetStockObject(BLACK_BRUSH));

    wchar_t txt[64]{};
    GetWindowTextW(d->hwndItem, txt, 64);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, fg);
    HFONT old = (HFONT)SelectObject(dc, g_fontUI);
    DrawTextW(dc, txt, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, old);
    if (d->itemState & ODS_FOCUS) DrawFocusRect(dc, &r);
}

static void DoAttach() {
    if (g_rbx.proc.ok()) { g_rbx.detach(); Log(L"desadjuntado"); }
    SetWindowTextW(g_status, L"buscando Roblox...");
    if (g_rbx.attach()) SetWindowTextW(g_status, L"adjuntado  -  listo");
    else                SetWindowTextW(g_status, L"Roblox no detectado");
}

static void DoExec() {
    if (!g_rbx.ready) { Log(L"adjunta primero (boton Attach)"); return; }
    std::string src = GetEditorText();
    if (src.empty()) { Log(L"editor vacio"); return; }
    Log(L"--- ejecutando (%llu bytes) ---", (u64)src.size());
    g_rbx.run(src);
}

static void DoOpen() {
    wchar_t path[MAX_PATH]{};
    OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd; ofn.lpstrFilter = L"Scripts Lua (*.lua)\0*.lua\0Todos\0*.*\0";
    ofn.lpstrFile = path; ofn.nMaxFile = MAX_PATH; ofn.Flags = OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD sz = GetFileSize(f, nullptr);
    std::string s(sz, '\0');
    DWORD rd = 0; ReadFile(f, s.data(), sz, &rd, nullptr); CloseHandle(f);
    s.resize(rd);
    SetEditorText(s);
    Log(L"abierto: %s", path);
}

static void DoSave() {
    wchar_t path[MAX_PATH] = L"script.lua";
    OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd; ofn.lpstrFilter = L"Scripts Lua (*.lua)\0*.lua\0";
    ofn.lpstrFile = path; ofn.nMaxFile = MAX_PATH; ofn.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&ofn)) return;
    std::string s = GetEditorText();
    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD wr = 0; WriteFile(f, s.data(), (DWORD)s.size(), &wr, nullptr); CloseHandle(f);
    Log(L"guardado: %s", path);
}

static LRESULT CALLBACK WndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hw;
        g_brBg    = CreateSolidBrush(C_BG);
        g_brPanel = CreateSolidBrush(C_PANEL);
        g_brEdit  = CreateSolidBrush(C_EDITBG);

        g_fontUI = CreateFontW(-14, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
                               OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                               DEFAULT_PITCH, L"Segoe UI");
        g_fontMono = CreateFontW(-15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                                 OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                 FIXED_PITCH, L"Consolas");

        g_status = CreateWindowW(L"STATIC", L"Roblox no detectado", WS_CHILD | WS_VISIBLE,
                                 0, 0, 10, 10, hw, (HMENU)IDC_STATUS, nullptr, nullptr);
        SendMessageW(g_status, WM_SETFONT, (WPARAM)g_fontUI, TRUE);

        const wchar_t* names[] = { L"Execute (F5)", L"Attach", L"Open", L"Save", L"Clear" };
        int ids[] = { IDC_EXEC, IDC_ATTACH, IDC_OPEN, IDC_SAVE, IDC_CLEAR };
        for (int i = 0; i < 5; ++i) {
            HWND b = CreateWindowW(L"BUTTON", names[i], WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                   0, 0, 10, 10, hw, (HMENU)(INT_PTR)ids[i], nullptr, nullptr);
            SendMessageW(b, WM_SETFONT, (WPARAM)g_fontUI, TRUE);
        }

        g_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
                                 ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN,
                                 0, 0, 10, 10, hw, (HMENU)IDC_EDIT, nullptr, nullptr);
        SendMessageW(g_edit, WM_SETFONT, (WPARAM)g_fontMono, TRUE);
        SendMessageW(g_edit, EM_SETLIMITTEXT, 0, 0);
        SetWindowTheme(g_edit, L"DarkMode_Explorer", nullptr);

        g_logBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                   WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                   ES_READONLY | ES_AUTOVSCROLL,
                                   0, 0, 10, 10, hw, (HMENU)IDC_LOGBOX, nullptr, nullptr);
        SendMessageW(g_logBox, WM_SETFONT, (WPARAM)g_fontMono, TRUE);

        Log(L"67 v1.0  -  executor externo");
        Log(L"abre Roblox y pulsa Attach (o espera al auto-attach).");

        SetTimer(hw, 1, 1500, nullptr);
        SetTimer(hw, 2, 300, nullptr);
        RegisterHotKey(hw, 10, 0, VK_F5);
        return 0;
    }
    case WM_TIMER:
        if (wp == 1) {
            bool alive = g_rbx.proc.ok() && WaitForSingleObject(g_rbx.proc.h, 0) == WAIT_TIMEOUT;
            if (!alive) {
                if (g_rbx.proc.ok()) { Log(L"Roblox se cerro."); g_rbx.detach(); }
                SetWindowTextW(g_status, L"esperando Roblox...");
                if (FindPid(cfg::kTarget)) DoAttach();
            }
        } else if (wp == 2) {
            RefreshLog();
        }
        return 0;
    case WM_HOTKEY:
        if (wp == 10) DoExec();
        return 0;
    case WM_DRAWITEM:
        DrawBtn((DRAWITEMSTRUCT*)lp);
        return TRUE;
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        HWND c = (HWND)lp;
        SetTextColor(dc, C_TEXT);
        SetBkColor(dc, C_EDITBG);
        if (c == g_status) return (LRESULT)g_brBg;
        return (LRESULT)g_brEdit;
    }
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(hw, &rc);
        FillRect((HDC)wp, &rc, g_brBg);
        return 1;
    }
    case WM_SIZE:
        Layout(hw);
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_ATTACH: DoAttach(); break;
        case IDC_EXEC:   DoExec();   break;
        case IDC_CLEAR:  SetWindowTextW(g_edit, L""); break;
        case IDC_OPEN:   DoOpen();   break;
        case IDC_SAVE:   DoSave();   break;
        }
        return 0;
    case WM_CLOSE:
        KillTimer(hw, 1); KillTimer(hw, 2);
        g_rbx.detach();
        DestroyWindow(hw);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hw, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, LPWSTR, int) {
    EnableDebugPrivilege();

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hi;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"Cls67";
    wc.hIcon         = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    HWND hw = CreateWindowExW(0, L"Cls67", cfg::kTitle, WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT, 980, 700,
                              nullptr, nullptr, hi, nullptr);
    ShowWindow(hw, SW_SHOW);
    UpdateWindow(hw);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
    return 0;
}
