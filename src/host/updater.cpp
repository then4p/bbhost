#include "host/updater.h"

#include "bbhost_version.h"
#include "core/config.h"
#include "core/sha256.h"
#include "log.h"
#include "replay/json.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <string_view>
#include <thread>
#include <vector>

#if defined(BBHOST_HAVE_CURL)
#include <curl/curl.h>
#endif
#if defined(_WIN32)
#include <windows.h>
#else
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif
#if defined(BBHOST_HAVE_SDL3)
#include <SDL3/SDL.h>
#endif

namespace updater {

namespace {

namespace fs = std::filesystem;

// The release signing key's public half. The private half signs each
// release's SHA256SUMS and the official plugins in the release workflow (the
// RELEASE_SIGNING_KEY secret); no official plugin it did not sign is loaded.
constexpr std::uint8_t kReleaseKey[32] = {
    0xce, 0x83, 0x68, 0x4e, 0xe9, 0x4e, 0xc4, 0xb9, 0xc9, 0x1c, 0xf6, 0x24, 0x7a, 0x23, 0xd0, 0x8f,
    0x50, 0x1c, 0xdd, 0x7a, 0x19, 0x73, 0x3c, 0x83, 0x48, 0xca, 0x3e, 0xd6, 0xae, 0xa7, 0xad, 0x62,
};
}  // namespace

const std::uint8_t* release_key() { return kReleaseKey; }

namespace {
constexpr const char* kDefaultSource = "https://api.github.com/repos/droogie/bbhost/releases/latest";
constexpr std::size_t kMaxDownload = 256u << 20;

std::mutex g_mu;
std::string g_status, g_detail;  // under g_mu
std::string g_tag, g_page;       // under g_mu: the newer release and its page, when there is one
std::atomic<bool> g_busy{false}, g_checked{false}, g_available{false};

// The newer release's package for this install (self-update), under g_mu.
struct Package {
    std::string name, url, sums_url, sig_url;  // the assets' API URLs
    long long size = 0;
};
Package g_pkg;
std::atomic<bool> g_installing{false}, g_restart_asked{false};
std::atomic<int> g_progress{-1};  // the package download's percent, -1 before it starts
std::string g_install_tag;        // under g_mu: what is being installed
std::string g_staged_dir;         // under g_mu: the unpacked package, once it is ready
std::vector<std::string> g_argv;  // main's arguments (apply_if_asked), for relaunch

void set_lines(const std::string& status, const std::string& detail) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_status = status;
    g_detail = detail;
}

fs::path exe_path() {
#if defined(_WIN32)
    std::wstring buf(32768, L'\0');
    const DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    buf.resize(n);
    return fs::path(buf);
#else
    std::error_code ec;
    return fs::read_symlink("/proc/self/exe", ec);
#endif
}

std::string read_token() {
    const std::string& file = config().update_token_file;
    if (file.empty()) return {};
    std::ifstream in(file, std::ios::binary);
    std::string t((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    while (!t.empty() && (t.back() == '\n' || t.back() == '\r' || t.back() == ' ')) t.pop_back();
    return t;
}

struct Fetch {
    long status = 0;
    std::string body, error;
    bool ok() const { return error.empty() && status >= 200 && status < 300; }
};

#if defined(BBHOST_HAVE_CURL)
int progress_cb(void* user, curl_off_t total, curl_off_t now, curl_off_t, curl_off_t) {
    if (user && total > 0) static_cast<std::atomic<int>*>(user)->store(static_cast<int>(now * 100 / total));
    return 0;
}

std::size_t write_cb(char* ptr, std::size_t size, std::size_t nmemb, void* user) {
    auto* s = static_cast<std::string*>(user);
    if (s->size() + size * nmemb > kMaxDownload) return 0;  // ends the transfer
    s->append(ptr, size * nmemb);
    return size * nmemb;
}
#endif

// A GET to GitHub. Only the update token goes with it (and only to
// api.github.com: curl leaves a custom Authorization header behind when a
// redirect takes it to another host, which is where asset downloads go).
Fetch fetch(const std::string& url, bool binary, int timeout_ms, const std::string& token, std::atomic<int>* progress = nullptr) {
    Fetch r;
#if defined(BBHOST_HAVE_CURL)
    static std::once_flag once;
    std::call_once(once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
    CURL* c = curl_easy_init();
    if (!c) {
        r.error = "curl_easy_init failed";
        return r;
    }
    struct curl_slist* h = nullptr;
    h = curl_slist_append(h, binary ? "Accept: application/octet-stream" : "Accept: application/vnd.github+json");
    h = curl_slist_append(h, "X-GitHub-Api-Version: 2022-11-28");
    if (!token.empty() && url.rfind("https://api.github.com/", 0) == 0) {
        h = curl_slist_append(h, ("Authorization: Bearer " + token).c_str());
    }
    const std::string agent = std::string("bbhost/") + BBHOST_VERSION;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_USERAGENT, agent.c_str());
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, 15000L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &r.body);
    if (progress) {
        curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, progress_cb);
        curl_easy_setopt(c, CURLOPT_XFERINFODATA, progress);
        curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
    }
#if defined(_WIN32)
    curl_easy_setopt(c, CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_REVOKE_BEST_EFFORT));
#endif
    const CURLcode rc = curl_easy_perform(c);
    if (rc != CURLE_OK) r.error = curl_easy_strerror(rc);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(h);
    curl_easy_cleanup(c);
#else
    (void)url;
    (void)binary;
    (void)timeout_ms;
    (void)token;
    (void)progress;
    r.error = "this build has no HTTP client";
#endif
    return r;
}

Fetch fetch(const std::string& url, bool binary, int timeout_ms) { return fetch(url, binary, timeout_ms, read_token()); }

// The newer release's assets for this install's package (self-update): the
// package, SHA256SUMS and its signature - all three, or none.
Package find_package(const std::string& body, const std::string& tag) {
    Package p;
    const std::string want = package_name(install_flavour(), tag);
    json::Value v;
    std::string err;
    if (want.empty() || !json::parse(body, v, err) || v.type != json::Value::Type::Object) return p;
    const json::Value* a = v.find("assets");
    if (!a || a->type != json::Value::Type::Array) return p;
    for (const json::Value& asset : a->array) {
        const json::Value* n = asset.find("name");
        const json::Value* u = asset.find("url");
        if (!n || !u || n->type != json::Value::Type::String || u->type != json::Value::Type::String) continue;
        if (u->string.rfind("https://api.github.com/", 0) != 0) continue;
        if (n->string == want) {
            p.url = u->string;
            if (const json::Value* sz = asset.find("size"); sz && sz->type == json::Value::Type::Number) p.size = static_cast<long long>(sz->number);
        } else if (n->string == "SHA256SUMS") {
            p.sums_url = u->string;
        } else if (n->string == "SHA256SUMS.sig") {
            p.sig_url = u->string;
        }
    }
    if (p.url.empty() || p.sums_url.empty() || p.sig_url.empty()) return Package{};
    p.name = want;
    return p;
}

void check_thread(const std::string& source, const std::string& token) {
    const Fetch f = fetch(source, false, 20000, token);
    std::string tag, page;
    if (!f.ok() || !parse_release(f.body, tag, page)) {
        std::string why = !f.error.empty() ? f.error : f.ok() ? "the answer is not a release" : "HTTP " + std::to_string(f.status);
        if (f.status == 404) {
            why = token.empty() ? "no releases visible (a private repository needs update.token_file)" : "no release found";
        }
        host_log("update: check failed: %s", why.c_str());
        set_lines(std::string("bbhost ") + BBHOST_VERSION + " - could not check for updates", why);
        g_busy.store(false);
        return;
    }
    if (!is_newer(tag, BBHOST_VERSION)) {
        host_log("update: %s is current (latest release %s)", BBHOST_VERSION, tag.c_str());
        set_lines(std::string("bbhost ") + BBHOST_VERSION + " - up to date", "Latest release: " + tag);
        g_available.store(false);
        g_busy.store(false);
        return;
    }
    const Package pkg = find_package(f.body, tag);
    const std::string how = !pkg.name.empty()             ? "installable as " + pkg.name
                            : install_flavour().empty() ? std::string("not an installed package: from the release page")
                                                        : std::string("no signed package for this install: from the release page");
    host_log("update: %s is available (this is %s): %s; %s", tag.c_str(), BBHOST_VERSION, page.c_str(), how.c_str());
    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_tag = tag;
        g_page = page;
        g_pkg = pkg;
        g_status = "bbhost " + tag + " is available (this is " + BBHOST_VERSION + ")";
        g_detail = !pkg.name.empty() ? "Update and restart installs " + pkg.name + " over this copy" : page;
    }
    g_available.store(true);
    g_busy.store(false);
    // BBHOST_UPDATE_TEST=install: the whole self-update with no one to click
    // (download, verify, unpack, restart, put in place).
    if (const char* e = std::getenv("BBHOST_UPDATE_TEST"); e && std::string(e) == "install" && !pkg.name.empty()) install();
}

// A check on a thread of its own, unless one is running. `delay` keeps it out
// of the boot's busiest seconds. What it asks with is read here: main loads
// the configuration again after the setup window's Play, while a check the
// window began may still be running.
void begin_check(bool delay) {
    if (g_installing.load() || g_busy.exchange(true)) return;
    g_checked.store(true);
    set_lines(std::string("bbhost ") + BBHOST_VERSION + " - checking for updates...", "");
    std::string source = config().update_source.empty() ? kDefaultSource : config().update_source;
    std::thread([delay, source = std::move(source), token = read_token()] {
        if (delay) std::this_thread::sleep_for(std::chrono::seconds(5));
        check_thread(source, token);
    }).detach();
}

bool write_file(const fs::path& p, const std::string& data) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(out);
}

// --- self-update ---------------------------------------------------------

fs::path exe_dir() { return exe_path().parent_path(); }

#if defined(_WIN32)
constexpr const char* kExeName = "bbhost.exe";

// One argument as CommandLineToArgvW reads it back.
std::wstring quote_arg(const std::wstring& a) {
    if (!a.empty() && a.find_first_of(L" \t\"") == std::wstring::npos) return a;
    std::wstring q = L"\"";
    std::size_t slashes = 0;
    for (wchar_t ch : a) {
        if (ch == L'\\') {
            ++slashes;
            continue;
        }
        q.append(ch == L'"' ? slashes * 2 + 1 : slashes, L'\\');
        q += ch;
        slashes = 0;
    }
    q.append(slashes * 2, L'\\');
    return q + L"\"";
}
constexpr const char* kApplyName = "apply.exe";

// The command line after its first argument (the program), as Windows splits
// it: quoted up to the next quote, else up to the first space or tab.
std::wstring after_arg0(const std::wstring& cmd) {
    std::size_t i = 0;
    if (i < cmd.size() && cmd[i] == L'"') {
        i = cmd.find(L'"', 1);
        i = i == std::wstring::npos ? cmd.size() : i + 1;
    } else {
        while (i < cmd.size() && cmd[i] != L' ' && cmd[i] != L'\t') ++i;
    }
    while (i < cmd.size() && (cmd[i] == L' ' || cmd[i] == L'\t')) ++i;
    return cmd.substr(i);
}
#else
constexpr const char* kExeName = "bbhost";
constexpr const char* kApplyName = "apply";
#endif

// A program run to its end with no window: its exit code, -1 when it did not start.
int run_wait(const fs::path& program, const std::vector<fs::path>& args) {
#if defined(_WIN32)
    std::wstring cmd = quote_arg(program.wstring());
    for (const fs::path& a : args) cmd += L" " + quote_arg(a.wstring());
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(program.wstring().c_str(), cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return -1;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
#else
    std::vector<std::string> owned{program.string()};
    for (const fs::path& a : args) owned.push_back(a.string());
    std::vector<char*> argv;
    for (std::string& a : owned) argv.push_back(a.data());
    argv.push_back(nullptr);
    pid_t pid = 0;
    if (posix_spawnp(&pid, owned[0].c_str(), nullptr, nullptr, argv.data(), environ) != 0) return -1;
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
#endif
}

// The archive unpacked into `dir`: Windows' own tar.exe (bsdtar, which reads
// zip too; in System32 since Windows 10 1803), tar on Linux.
bool unpack(const fs::path& archive, const fs::path& dir) {
#if defined(_WIN32)
    wchar_t sys[MAX_PATH];
    const UINT n = GetSystemDirectoryW(sys, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    const fs::path tar = fs::path(std::wstring(sys, n)) / L"tar.exe";
    return run_wait(tar, {L"-xf", archive, L"-C", dir}) == 0;
#else
    return run_wait("tar", {"-xzf", archive, "-C", dir}) == 0;
#endif
}

void install_thread() {
    Package pkg;
    std::string tag;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        pkg = g_pkg;
        tag = g_tag;
        g_install_tag = tag;
    }
    auto fail = [&](const std::string& why) {
        host_log("update: %s not installed: %s", tag.c_str(), why.c_str());
        set_lines("bbhost " + tag + " was not installed", why);
        g_progress.store(-1);
        g_installing.store(false);
    };
    set_lines("Updating to bbhost " + tag + "...", "Checking the release's signature");
    const Fetch sums = fetch(pkg.sums_url, true, 30000);
    const Fetch sig = fetch(pkg.sig_url, true, 30000);
    if (!sums.ok() || !sig.ok()) {
        const Fetch& bad = sums.ok() ? sig : sums;
        return fail("could not download its checksums (" + (bad.error.empty() ? "HTTP " + std::to_string(bad.status) : bad.error) + ")");
    }
    if (!signature_ok(sums.body, sig.body, kReleaseKey)) return fail("its checksums are not signed by the release key");
    const std::string want = manifest_hash(sums.body, pkg.name);
    if (want.empty()) return fail("its checksums do not list " + pkg.name);
    char size[48] = "";
    if (pkg.size > 0) std::snprintf(size, sizeof(size), " (%.0f MB)", static_cast<double>(pkg.size) / 1048576.0);
    set_lines("Updating to bbhost " + tag + "...", "Downloading " + pkg.name + size);
    host_log("update: downloading %s%s", pkg.name.c_str(), size);
    g_progress.store(0);
    const Fetch body = fetch(pkg.url, true, 1800000, read_token(), &g_progress);
    if (!body.ok()) return fail("the download failed (" + (body.error.empty() ? "HTTP " + std::to_string(body.status) : body.error) + ")");
    g_progress.store(100);
    const std::string got = sha256_hex(reinterpret_cast<const std::uint8_t*>(body.body.data()), body.body.size());
    if (got != want) return fail("the download does not match its signed checksum");

    // Unpacked beside the install, in a folder of its own; the install is not
    // touched until this process has ended (apply_if_asked).
    set_lines("Updating to bbhost " + tag + "...", "Unpacking");
    const fs::path base = exe_dir() / ".update";
    const fs::path work = base / tag;
    std::error_code ec;
    fs::remove_all(work, ec);
    fs::create_directories(work, ec);
    if (ec) return fail("cannot make " + work.string() + ": " + ec.message());
    const fs::path archive = base / pkg.name;
    if (!write_file(archive, body.body)) return fail("cannot write " + archive.string());
    const bool unpacked = unpack(archive, work);
    fs::remove(archive, ec);
    if (!unpacked) return fail("could not unpack " + pkg.name);
    // The package's one folder (bbhost-win-<tag>/...), with the executable in it.
    fs::path root;
    for (const auto& e : fs::directory_iterator(work, ec)) {
        std::error_code xec;
        if (e.is_directory(xec) && fs::exists(e.path() / kExeName, xec)) root = e.path();
    }
    if (root.empty()) return fail(pkg.name + " holds no " + kExeName);
    // What puts it in place is this build's own code, a copy of this
    // executable (.update/apply.exe): the release being installed may be one
    // that cannot install itself (an upstream release).
    fs::copy_file(exe_path(), base / kApplyName, fs::copy_options::overwrite_existing, ec);
    if (ec) return fail("cannot copy the updater to " + (base / kApplyName).string() + ": " + ec.message());
    host_log("update: %s downloaded, verified (signature and checksum) and unpacked into %s", tag.c_str(), root.string().c_str());
    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_staged_dir = root.string();
        g_status = "bbhost " + tag + " is ready";
        g_detail = "Restarting into it";
    }
    g_restart_asked.store(true);
    // g_installing stays set: nothing else starts before the restart.
}

// The first file of the install the package would replace that something
// still holds (the setup window that started the game with --no-setup holds
// bbhost.exe; a plugin another bbhost loaded): "" when none. Nothing is
// renamed aside to get round one - the player closes what holds it.
std::string locked_file(const fs::path& from, const fs::path& to) {
#if defined(_WIN32)
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(from, ec); !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        std::error_code xec;
        if (it->is_directory(xec)) continue;
        const fs::path dst = to / fs::relative(it->path(), from, xec);
        if (xec || !fs::exists(dst, xec)) continue;
        HANDLE h = CreateFileW(dst.wstring().c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            const DWORD err = GetLastError();
            if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION || err == ERROR_ACCESS_DENIED) return dst.string();
            continue;
        }
        CloseHandle(h);
    }
#else
    // Linux locks no file; a running executable refuses the copy (ETXTBSY),
    // which install_tree reports the same way.
    (void)from;
    (void)to;
#endif
    return {};
}

// The package's files over the install, each overwritten. Nothing else in the
// install is touched: a bbhost.toml, data/, logs/ and plugins of the
// player's own stay.
bool install_tree(const fs::path& from, const fs::path& to, std::string& error, int& files) {
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(from, ec); !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        const fs::path rel = fs::relative(it->path(), from, ec);
        if (ec) break;
        const fs::path dst = to / rel;
        if (it->is_directory(ec)) {
            fs::create_directories(dst, ec);
            if (ec) break;
            continue;
        }
        std::error_code cec;
        fs::copy_file(it->path(), dst, fs::copy_options::overwrite_existing, cec);
        if (cec) {
            error = dst.string() + ": " + cec.message();
            return false;
        }
        // A plugin the plugin manager fetched while it was loaded waits as
        // <name>.dll.new for the next start, which would put that older one
        // back over this: the package's is newer.
        if (rel.begin() != rel.end() && *rel.begin() == "plugins") {
            std::error_code rec;
            fs::remove(fs::path(dst).concat(".new"), rec);
            fs::remove(fs::path(dst).concat(".new.sig"), rec);
        }
        ++files;
    }
    if (ec) {
        error = ec.message();
        return false;
    }
    return true;
}

// What an update left in .update (the updater copy, once it has ended): a
// few tries, as it may still be ending.
void cleanup_after_update() {
    const fs::path dir = exe_dir() / ".update";
    for (int i = 0; i < 6; ++i) {
        std::error_code ec;
        if (!fs::exists(dir, ec)) return;
        fs::remove_all(dir, ec);
        if (!ec) return;
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

// The player told why an update stopped: the log, and a message box on
// Windows (the updater copy has no window of its own).
void tell(const std::string& msg) {
    std::fprintf(stderr, "update: %s\n", msg.c_str());
    std::fflush(stderr);
#if defined(_WIN32)
    const int n = MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? n : 1, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), -1, w.data(), n);
    MessageBoxW(nullptr, w.c_str(), L"bbhost update", MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
#endif
}

void set_env(const char* k, const std::string& v) {
#if defined(_WIN32)
    // Both tables: the C runtime's (getenv) and the process's (what a child gets).
    _putenv_s(k, v.c_str());
    SetEnvironmentVariableA(k, v.empty() ? nullptr : v.c_str());
#else
    if (v.empty()) unsetenv(k);
    else setenv(k, v.c_str(), 1);
#endif
}

std::string take_env(const char* k) {
    const char* e = std::getenv(k);
    std::string v = e ? e : "";
    if (e) set_env(k, "");
    return v;
}

// `exe` started with `args` - on Windows the command line after the program,
// on Linux the arguments - its output where this one's goes (run-bbhost.bat's
// log), in `cwd`. `wait`: its exit code; else 0 once it has started. -1 when
// it did not start.
#if defined(_WIN32)
int spawn(const fs::path& exe, const std::wstring& args, const fs::path& cwd, bool wait) {
    std::wstring cmd = quote_arg(exe.wstring());
    if (!args.empty()) cmd += L" " + args;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe.wstring().c_str(), cmd.data(), nullptr, nullptr, TRUE, 0, nullptr, cwd.empty() ? nullptr : cwd.wstring().c_str(), &si,
                        &pi)) {
        std::fprintf(stderr, "update: could not start %s (CreateProcess error %lu)\n", exe.string().c_str(),
                     static_cast<unsigned long>(GetLastError()));
        return -1;
    }
    DWORD code = 0;
    if (wait) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &code);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}
#else
int spawn(const fs::path& exe, const std::vector<std::string>& args, const fs::path& cwd, bool wait) {
    std::vector<std::string> owned{exe.string()};
    owned.insert(owned.end(), args.begin(), args.end());
    std::vector<char*> argv;
    for (std::string& a : owned) argv.push_back(a.data());
    argv.push_back(nullptr);
    std::error_code ec;
    const fs::path here = fs::current_path(ec);
    if (!cwd.empty()) fs::current_path(cwd, ec);
    pid_t pid = 0;
    const int rc = posix_spawn(&pid, exe.c_str(), nullptr, nullptr, argv.data(), environ);
    if (!cwd.empty() && !here.empty()) fs::current_path(here, ec);
    if (rc != 0) {
        std::fprintf(stderr, "update: could not start %s\n", exe.c_str());
        return -1;
    }
    if (!wait) return 0;
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
#endif

}  // namespace

// --- official plugins ----------------------------------------------------

std::mutex g_plugins_mu;
std::string g_plugins_status;  // under g_plugins_mu
std::atomic<bool> g_plugins_busy{false};

void set_plugins_status(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_plugins_mu);
    g_plugins_status = s;
    host_log("plugins: %s", s.c_str());
}

#if defined(_WIN32)
constexpr const char* kPluginSuffix = "-windows.dll";
constexpr const char* kPluginExt = ".dll";
#else
constexpr const char* kPluginSuffix = "-linux.so";
constexpr const char* kPluginExt = ".so";
#endif

// Every bbhost-plugin-<name><suffix> of the latest release, with its .sig:
// verified against the release key, then written to <dir>/<name><ext>
// (+ .sig) - or <name><ext>.new when that file is in use (a loaded plugin on
// Windows), which plugins_load puts in place at the next start.
void fetch_plugins_thread(std::string dir) {
    set_plugins_status("looking for the latest official plugins...");
    const std::string source = config().update_source.empty() ? kDefaultSource : config().update_source;
    const Fetch f = fetch(source, false, 20000);
    json::Value v;
    std::string err;
    if (!f.ok() || !json::parse(f.body, v, err) || v.type != json::Value::Type::Object) {
        set_plugins_status("could not read the latest release: " + (!f.error.empty() ? f.error : "HTTP " + std::to_string(f.status)) +
                           (f.status == 404 && read_token().empty() ? " (a private repository needs update.token_file)" : ""));
        g_plugins_busy.store(false);
        return;
    }
    std::string tag;
    if (const json::Value* t = v.find("tag_name"); t && t->type == json::Value::Type::String) tag = t->string;
    std::map<std::string, std::string> files;  // asset name -> API url
    if (const json::Value* a = v.find("assets"); a && a->type == json::Value::Type::Array) {
        for (const json::Value& asset : a->array) {
            const json::Value* n = asset.find("name");
            const json::Value* u = asset.find("url");
            if (n && u && n->type == json::Value::Type::String && u->type == json::Value::Type::String) files[n->string] = u->string;
        }
    }
    std::error_code ec;
    fs::create_directories(dir, ec);
    int installed = 0, failed = 0;
    std::string names;
    for (const auto& [asset, url] : files) {
        const std::string prefix = "bbhost-plugin-", suffix = kPluginSuffix;
        if (asset.rfind(prefix, 0) != 0 || asset.size() <= prefix.size() + suffix.size() ||
            asset.compare(asset.size() - suffix.size(), suffix.size(), suffix) != 0)
            continue;
        const std::string name = asset.substr(prefix.size(), asset.size() - prefix.size() - suffix.size());
        auto sig_it = files.find(asset + ".sig");
        if (name.find_first_of("/\\.:") != std::string::npos || sig_it == files.end()) {
            ++failed;
            continue;
        }
        set_plugins_status("downloading " + name + "...");
        const Fetch bin = fetch(url, true, 300000);
        const Fetch sig = fetch(sig_it->second, true, 30000);
        if (!bin.ok() || !sig.ok() || !signature_ok(bin.body, sig.body, kReleaseKey)) {
            host_log("plugins: %s: %s", name.c_str(), !bin.ok() || !sig.ok() ? "download failed" : "the signature does not match: not installed");
            ++failed;
            continue;
        }
        // Written beside it and renamed over it: a running plugin keeps the
        // file it was loaded from (Linux), or the rename is refused because
        // it is loaded (Windows) and the next start puts the .new in place.
        const fs::path target = fs::path(dir) / (name + kPluginExt);
        const fs::path tmp = fs::path(target.string() + ".part");
        fs::path out = target;
        std::error_code rec;
        if (!write_file(tmp, bin.body)) {
            ++failed;
            continue;
        }
        fs::rename(tmp, target, rec);
        if (rec) {
            out = fs::path(target.string() + ".new");
            fs::rename(tmp, out, rec);
            if (rec) {
                fs::remove(tmp, rec);
                ++failed;
                continue;
            }
        }
        write_file(fs::path(out.string() + ".sig"), sig.body);
        ++installed;
        names += (names.empty() ? "" : ", ") + name;
    }
    if (!installed && !failed) {
        set_plugins_status("release " + tag + " has no official plugins for this platform");
    } else {
        set_plugins_status("release " + tag + ": " + std::to_string(installed) + " installed" + (names.empty() ? "" : " (" + names + ")") +
                           (failed ? ", " + std::to_string(failed) + " failed (see the log)" : "") + " - active from the next start");
    }
    g_plugins_busy.store(false);
}

const char* current_version() { return BBHOST_VERSION; }

void fetch_plugins(const std::string& dir) {
    if (g_plugins_busy.exchange(true)) return;
    std::thread(fetch_plugins_thread, dir).detach();
}

std::string plugins_status() {
    std::lock_guard<std::mutex> lk(g_plugins_mu);
    return g_plugins_status;
}

bool plugins_busy() { return g_plugins_busy.load(); }

void start() {
    {
        // The copy an older build's update set aside (bbhost.exe.old,
        // bbhost.old on Linux): gone once nothing runs it.
        std::error_code ec;
        const fs::path cur = exe_path();
        if (!cur.empty()) fs::remove(fs::path(cur).concat(".old"), ec);
        // A self-update's leftovers (.update: the updater copy that put this
        // build in place, which may still be ending): a little later.
        if (!cur.empty() && fs::exists(cur.parent_path() / ".update", ec)) {
            std::thread([] {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                cleanup_after_update();
            }).detach();
        }
    }
#if defined(BBHOST_RELEASE_BUILD)
    const bool release = true;
#else
    const bool release = false;
#endif
    // BBHOST_UPDATE_TEST=1: check whatever the build and settings say, and
    // log what is found.
    const bool test = std::getenv("BBHOST_UPDATE_TEST") != nullptr;
    if (config().headless && !test) return;  // nobody to offer it to
    if (g_checked.load()) return;            // the setup window has checked
    const int want = test ? 1 : config().update_check;
    set_lines(std::string("bbhost ") + BBHOST_VERSION, "");
    if (want == 0 || (want < 0 && !release)) {
        if (want < 0) set_lines(std::string("bbhost ") + BBHOST_VERSION, "Built from source: checks only when asked (update.check)");
        return;
    }
    begin_check(true);
}

void check_once() {
    if (!g_checked.load()) begin_check(false);
}

std::string status() {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_status;
}

std::string detail() {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_detail;
}

bool busy() { return g_busy.load(); }
bool update_available() { return g_available.load(); }

std::string latest_tag() {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_tag;
}

void check_now() { begin_check(false); }

bool open_release_page() {
    std::string url;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        url = g_page;
    }
    if (!g_available.load() || !release_page_ok(url)) return false;
#if defined(BBHOST_HAVE_SDL3)
    // The system's handler for links, the default browser: ShellExecute on
    // Windows, xdg-open on Linux (not waited for).
    if (SDL_OpenURL(url.c_str())) {
        host_log("update: opened %s", url.c_str());
        return true;
    }
    host_log("update: could not open %s: %s", url.c_str(), SDL_GetError());
#else
    // A build without SDL has no window, so nothing calls this.
    host_log("update: no browser to open %s in", url.c_str());
#endif
    std::lock_guard<std::mutex> lk(g_mu);
    g_detail = "The browser did not open; the page is " + url;
    return false;
}

// --- self-update ---------------------------------------------------------

std::string install_flavour() {
    if (const char* e = std::getenv("BBHOST_UPDATE_FLAVOUR"); e && *e) return e;
    const fs::path d = exe_dir();
    if (d.empty()) return {};
    std::error_code ec;
    auto has = [&](const char* f) { return fs::exists(d / f, ec); };
    // A playtest kit is for the dev server: a release never replaces it.
    if (has("bbhost-playtest.toml")) return {};
#if defined(_WIN32)
    return has("run-bbhost.bat") && has("README.txt") ? "win" : "";
#else
    if (!has("run-bbhost.sh") || !has("README-linux.txt")) return {};
    return has("bbhost-steamdeck.toml") ? "steamdeck" : "linux";
#endif
}

bool can_install() {
    if (!g_available.load()) return false;
    std::lock_guard<std::mutex> lk(g_mu);
    return !g_pkg.name.empty();
}

void install() {
    if (!can_install() || g_busy.load() || g_installing.exchange(true)) return;
    std::thread(install_thread).detach();
}

bool installing() { return g_installing.load(); }

std::string install_label() {
    std::string tag;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        tag = g_install_tag;
    }
    const int p = g_progress.load();
    if (p >= 0 && p < 100) return "Downloading " + tag + " (" + std::to_string(p) + "%)";
    std::lock_guard<std::mutex> lk(g_mu);
    return g_staged_dir.empty() ? "Updating to " + tag + "..." : "Restarting into " + tag + "...";
}

bool take_restart_request() { return g_restart_asked.exchange(false); }

bool relaunch(bool setup) {
    std::string staged, tag;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        staged = g_staged_dir;
        tag = g_install_tag;
    }
    if (staged.empty()) return false;
    const fs::path apply = exe_dir() / ".update" / kApplyName;
    host_log("update: restarting to put %s in place (%s, by %s)", tag.c_str(), staged.c_str(), apply.string().c_str());
    set_env("BBHOST_UPDATE_TARGET", exe_dir().string());
    set_env("BBHOST_UPDATE_STAGED", staged);
    set_env("BBHOST_UPDATE_TAG", tag);
#if defined(_WIN32)
    set_env("BBHOST_UPDATE_PID", std::to_string(GetCurrentProcessId()));
    // This process's arguments after the program, as typed; --setup added
    // when the update began in the setup window, so it opens again.
    std::wstring args = after_arg0(GetCommandLineW());
    if (setup && args.find(L"--setup") == std::wstring::npos) args += args.empty() ? L"--setup" : L" --setup";
    std::fflush(nullptr);
    const bool started = spawn(apply, L"--apply-update" + (args.empty() ? std::wstring() : L" " + args), {}, false) == 0;
#else
    set_env("BBHOST_UPDATE_PID", std::to_string(getpid()));
    std::vector<std::string> args{"--apply-update"};
    if (g_argv.size() > 1) args.insert(args.end(), g_argv.begin() + 1, g_argv.end());
    bool has_setup = false;
    for (const std::string& a : args) has_setup = has_setup || a == "--setup";
    if (setup && !has_setup) args.push_back("--setup");
    std::fflush(nullptr);
    const bool started = spawn(apply, args, {}, false) == 0;
#endif
    if (started) return true;
    for (const char* k : {"BBHOST_UPDATE_TARGET", "BBHOST_UPDATE_STAGED", "BBHOST_UPDATE_TAG", "BBHOST_UPDATE_PID"}) set_env(k, "");
    set_lines("bbhost " + tag + " was not installed", "The updater did not start (" + apply.string() + ")");
    g_installing.store(false);
    return false;
}

void apply_if_asked(int argc, char** argv) {
    g_argv.assign(argv, argv + argc);
    if (argc < 2 || std::string(argv[1]) != "--apply-update") return;
    // This is .update/apply.exe, a copy of the build that downloaded the
    // update: it puts the unpacked package over the install, has the new
    // build compile its shaders, starts it, and ends.
    const std::string target = take_env("BBHOST_UPDATE_TARGET");
    const std::string staged = take_env("BBHOST_UPDATE_STAGED");
    const std::string tag = take_env("BBHOST_UPDATE_TAG");
    const std::string pid = take_env("BBHOST_UPDATE_PID");
    if (target.empty() || staged.empty()) {
        std::fprintf(stderr, "update: --apply-update without its target and package; nothing done\n");
        std::_Exit(2);
    }
    const std::string name = tag.empty() ? std::string("the new version") : "bbhost " + tag;
    std::fprintf(stderr, "update: waiting for bbhost %s to end, to put %s in place over %s\n", BBHOST_VERSION, name.c_str(), target.c_str());
    std::fflush(stderr);
    const unsigned long old = std::strtoul(pid.c_str(), nullptr, 10);
#if defined(_WIN32)
    if (old) {
        if (HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(old))) {
            WaitForSingleObject(h, 60000);
            CloseHandle(h);
        }
    }
    // The original arguments: this command line after the program and the flag.
    std::wstring args = after_arg0(GetCommandLineW());
    args = args.substr(std::min(args.size(), std::wstring(L"--apply-update").size()));
    while (!args.empty() && (args[0] == L' ' || args[0] == L'\t')) args.erase(0, 1);
#else
    for (int i = 0; old && i < 600 && kill(static_cast<pid_t>(old), 0) == 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const std::vector<std::string> args(argv + 2, argv + argc);
#endif
    const fs::path from(staged), to(target);
    // Something still holding a file the package replaces: a moment after
    // the old process ended (an antivirus scan) it lets go; the setup window
    // that started the game does not. Nothing is renamed aside to get round it.
    std::string held;
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (attempt) std::this_thread::sleep_for(std::chrono::seconds(1));
        held = locked_file(from, to);
        if (held.empty()) break;
    }
    if (!held.empty()) {
        tell("Could not update to " + name + ": " + held +
             " is in use. Close the bbhost setup window (and any other bbhost), then start bbhost and update again. "
             "Nothing was changed.");
        std::_Exit(1);
    }
    std::string err;
    int files = 0;
    bool ok = false;
    for (int attempt = 0; attempt < 3 && !ok; ++attempt) {
        if (attempt) std::this_thread::sleep_for(std::chrono::seconds(1));
        files = 0;
        ok = install_tree(from, to, err, files);
    }
    if (!ok) {
        tell("The update to " + name + " stopped part way: " + err + ". Its files are in " + from.string() +
             "; copy them over " + to.string() + " by hand, or download the release again.");
        std::_Exit(1);
    }
    std::fprintf(stderr, "update: %s installed (%d files)\n", name.c_str(), files);
    std::error_code ec;
    fs::remove_all(from.parent_path(), ec);  // .update/<tag>; this copy goes at the next start of a build that knows it
    const fs::path exe = to / kExeName;
    // The new build's shaders: --compile-shaders clears caches another
    // translator made (at its GPU start) and builds every one again, and with
    // current caches finds them built. Its progress goes to the log.
    std::fprintf(stderr, "update: %s compiles its shaders before the game starts (a few minutes when they changed)\n", name.c_str());
    std::fflush(stderr);
#if defined(_WIN32)
    if (HANDLE con = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr); con != INVALID_HANDLE_VALUE) {
        const std::string line = "\n bbhost is updating to " + (tag.empty() ? std::string("a new version") : tag) +
                                 ": compiling shaders, the game starts when they are done.\n";
        DWORD wrote = 0;
        WriteFile(con, line.data(), static_cast<DWORD>(line.size()), &wrote, nullptr);
        CloseHandle(con);
    }
    const int rc = spawn(exe, L"--compile-shaders" + (args.empty() ? std::wstring() : L" " + args), to, true);
#else
    std::vector<std::string> compile_args{"--compile-shaders"};
    compile_args.insert(compile_args.end(), args.begin(), args.end());
    const int rc = spawn(exe, compile_args, to, true);
#endif
    std::fprintf(stderr, "update: shader compile ended (exit %d); starting %s\n", rc, name.c_str());
    std::fflush(nullptr);
    std::_Exit(spawn(exe, args, to, false) == 0 ? 0 : 1);
}

}  // namespace updater
