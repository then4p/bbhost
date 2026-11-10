// The update check, against GitHub releases (CONTRIBUTING.md, "Releasing"). A
// release build looks for a newer release at start; the F10 screen's UPDATES
// rows and the setup window say what it found.
//
// Self-update: an installed package (the Windows zip, the Linux tarball or
// the Steam Deck kit, told apart by the files beside the executable) updates
// to the same package of the newer release. The setup window's "vX is out"
// button and F10's "Update and restart" download it, check it against the
// signed SHA256SUMS, unpack it into <exe dir>/.update and restart. The OLD
// build applies it, so any release can be installed - an upstream one that
// has none of this code too: a copy of this executable (.update/apply.exe)
// is started with --apply-update, and this process ends. The copy waits for
// it, checks that nothing holds a file the package replaces (the setup
// window that started the game does: the player is told to close it, and
// nothing is renamed aside to get round it), copies the package over the
// install, runs the new build's `--compile-shaders` (which clears shader
// caches another translator made and builds them again) and waits, then
// starts the new build with the original arguments, its output going where
// this one's went (run-bbhost.bat's log). The next start of a build that
// knows .update removes it. A build that is not an installed package (built
// from source, a playtest kit) opens the release page instead.
//
// update.source is the "releases/latest" API URL; a private repository's
// needs update.token_file. Nothing is sent but that token and a user agent:
// never the account's.
//
// Each release carries the bare executables under the same names every time
// (bbhost.exe, bbhost), SHA256SUMS and SHA256SUMS.sig, besides the packages.
// Older builds' updater looked for bbhost-<tag>-windows.exe; finding none, it
// says to get the release from its page. The release key below signs
// SHA256SUMS and the official plugins.
#pragma once

#include <cstdint>
#include <string>

namespace updater {

// This build's version (BBHOST_VERSION: "v0.1.0", "v0.1.0-3-gabc1234",
// "v0.0.0-<rev>", "+" for a changed tree).
const char* current_version();

// At start: the copy an older build's update set aside removed (every start),
// and the check begun on a thread of its own when update.check (or a release
// build) says so and there is a window to offer it in - unless the setup
// window has checked already.
// BBHOST_UPDATE_TEST=1 checks regardless, headless too, and logs what it finds;
// BBHOST_UPDATE_TEST=install also installs what it finds and restarts.
void start();

// The setup window, while its box is checked: a check at once, unless one has
// run or is running.
void check_once();

// The F10 rows and the setup window.
std::string status();      // "bbhost v0.1.0 - up to date", "bbhost v0.2.0 is available (this is v0.1.0)", ...
std::string detail();      // why a check failed, or the newer release's page
bool busy();               // a check is running
void check_now();          // look again (the "Check for updates" row)
bool update_available();   // a newer release was found
std::string latest_tag();  // its tag ("v0.2.0"), "" until one is found
// Its page in the browser (the "Open the release page" row, the setup
// window's button): false when there is none or the browser did not open.
bool open_release_page();

// --- self-update ---
// This install's package: "win", "linux", "steamdeck", or "" when bbhost does
// not run from an installed package (BBHOST_UPDATE_FLAVOUR overrides, for
// tests).
std::string install_flavour();
// A newer release with a signed package for this install was found.
bool can_install();
// Downloads, verifies and unpacks it on a thread of its own; when it is
// ready, a restart is asked for (take_restart_request) - the setup window and
// the game's loop take it. Nothing when it cannot install.
void install();
bool installing();
// The setup window's button while installing: "Downloading v0.2.31 (45%)".
std::string install_label();
// Taken once, by whoever is running the window: the setup window or the game.
bool take_restart_request();
// The updater copy started (.update/apply.exe --apply-update, the target,
// this process's id and the unpacked package in BBHOST_UPDATE_* variables),
// with this process's arguments; `setup` adds --setup so the setup window
// opens again. The caller exits right after (true) - false when it could not
// be started.
bool relaunch(bool setup);
// main, first thing: the arguments kept for relaunch; and when this process
// is the updater copy (--apply-update), the update applied and the new build
// started - this process then exits without returning.
void apply_if_asked(int argc, char** argv);

// The release signing key's public half (32 bytes): what signs SHA256SUMS,
// and the official plugins (host/plugins.cpp).
const std::uint8_t* release_key();

// The official plugins of the latest release, each verified against the
// release key, into `dir` (the plugin manager's "Get official plugins"). On
// a thread of its own; plugins_status() says how it went.
void fetch_plugins(const std::string& dir);
std::string plugins_status();
bool plugins_busy();

// The pieces, for tests (tests/updater_test.cpp).
// "v1.2.3..." -> 1, 2, 3; false when it does not start that way.
bool parse_version(const std::string& v, int out[3]);
// The release tag is newer than this build: a higher major.minor.patch. A
// build past a tag ("v0.1.0-3-g...") is that tag's version, so the next
// release is newer and the same tag is not.
bool is_newer(const std::string& tag, const std::string& current);
// The manifest's Ed25519 signature (64 raw bytes) against `public_key` (32).
bool signature_ok(const std::string& manifest, const std::string& signature, const std::uint8_t public_key[32]);
// What a "releases/latest" answer says: the release's tag, and the page to
// open for it - its html_url, else bbhost's page for the tag, else bbhost's
// latest release. False when the answer is not a release (no JSON object, no
// tag).
bool parse_release(const std::string& body, std::string& tag, std::string& page);
// SHA256SUMS's hash for `name` (lower-case hex), "" when it is not listed.
std::string manifest_hash(const std::string& manifest, const std::string& name);
// The release asset of a flavour's package: "bbhost-win-v0.2.31.zip",
// "bbhost-linux-v0.2.31.tar.gz", "bbhost-steamdeck-v0.2.31.tar.gz"; "" for
// another flavour.
std::string package_name(const std::string& flavour, const std::string& tag);
// A page the browser may be sent to. It comes from the network, so only
// https://github.com/ and only the characters a release page needs.
bool release_page_ok(const std::string& url);

}  // namespace updater
