#include "pki/license.hpp"

#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/log.hpp"
#include "pki/update.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstdio>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <vector>

namespace pki {
namespace {

// ⚠️ PINNED, AND COMPILED IN ON PURPOSE. A public key read from a path is a public key an
// operator can replace, which makes every signature below prove only that somebody had a
// key. This one ships inside the binary, so a forged licence needs a rebuilt binary — at
// which point the honest answer is that they removed the licence code, not that they fooled
// it.
const char kLicensePubKey[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8jA/cqQ5x4h5gl3tSlVhhq1mzh3z\n"
    "WegN8GOvTUGHTqIlPvmCl7U0QeA8kx8uKg4L/aHkRiVv737fEf/xJVkzxw==\n"
    "-----END PUBLIC KEY-----\n";

// The evaluation every build carries. Identical for everyone, and signed with the same key as
// a customer licence so it travels the one code path. It grants nothing, so one number for
// all of them costs nothing.
const char kEvalLicense[] =
    "-----BEGIN FASTPKI LICENSE-----\n"
    "number: FPK-EVAL\n"
    "tier: evaluation\n"
    "period_days: 30\n"
    "-----END FASTPKI LICENSE-----\n"
    "-----BEGIN FASTPKI LICENSE SIGNATURE-----\n"
    "MEUCIA1yrfaSZmauqi88wfKPM4WUP+Pcd2SY+WmzOOXIF+gYAiEA0UUK+45cdRzS\n"
    "EQV4Aq4UB2vReQiNpkwd6GIfJE2tbyg=\n"
    "-----END FASTPKI LICENSE SIGNATURE-----\n";

const char kBodyBegin[] = "-----BEGIN FASTPKI LICENSE-----";
const char kBodyEnd[]   = "-----END FASTPKI LICENSE-----";
const char kSigBegin[]  = "-----BEGIN FASTPKI LICENSE SIGNATURE-----";
const char kSigEnd[]    = "-----END FASTPKI LICENSE SIGNATURE-----";

// ⚠️ ISO DATES COMPARE AS STRINGS, AND THAT IS WHY THE FORMAT IS FIXED. YYYY-MM-DD sorts the
// same as text and as a date, so no calendar arithmetic, no timezone database and nothing that
// can be wrong in a leap year. It does mean a value that is not a date must not silently
// compare as one, which is what this insists on.
bool valid_iso_date(const std::string& s) {
    if (s.size() != 10 || s[4] != '-' || s[7] != '-') return false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (i == 4 || i == 7) continue;
        if (s[i] < '0' || s[i] > '9') return false;
    }
    const int m = (s[5] - '0') * 10 + (s[6] - '0');
    const int d = (s[8] - '0') * 10 + (s[9] - '0');
    return m >= 1 && m <= 12 && d >= 1 && d <= 31;
}

std::string fmt_date(std::tm tm) {
    char buf[11];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return buf;
}

std::tm gm(std::time_t t) {
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    return tm;
}

std::string today_utc(std::time_t now) { return fmt_date(gm(now)); }

// Add days to a YYYY-MM-DD date. timegm/mktime does the calendar; a day is 86400 seconds in
// UTC, with no daylight saving to step on.
std::string date_plus_days(const std::string& date, int days) {
    if (!valid_iso_date(date)) return {};
    std::tm tm{};
    tm.tm_year = std::stoi(date.substr(0, 4)) - 1900;
    tm.tm_mon  = std::stoi(date.substr(5, 2)) - 1;
    tm.tm_mday = std::stoi(date.substr(8, 2));
    tm.tm_hour = 12;   // midday, so a rounding error cannot move the date
#if defined(_WIN32)
    const std::time_t base = _mkgmtime(&tm);
#else
    const std::time_t base = timegm(&tm);
#endif
    if (base == static_cast<std::time_t>(-1)) return {};
    return fmt_date(gm(base + static_cast<std::time_t>(days) * 86400));
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// The text strictly between a pair of marker lines, as it appears in the file. `found` says
// whether both markers were present, so an empty section and a missing one differ.
std::string between(const std::string& text, const char* begin, const char* end, bool& found) {
    found = false;
    const size_t b = text.find(begin);
    if (b == std::string::npos) return {};
    const size_t bl = text.find('\n', b);
    if (bl == std::string::npos) return {};
    const size_t e = text.find(end, bl);
    if (e == std::string::npos) return {};
    found = true;
    return text.substr(bl + 1, e - bl - 1);
}

std::vector<unsigned char> b64_decode(const std::string& in) {
    std::vector<unsigned char> out(in.size());            // decoded is always smaller
    std::unique_ptr<BIO, decltype(&BIO_free_all)> b64{BIO_new(BIO_f_base64()), &BIO_free_all};
    if (!b64) return {};
    BIO* mem = BIO_new_mem_buf(in.data(), static_cast<int>(in.size()));
    if (!mem) return {};
    BIO_push(b64.get(), mem);                             // b64 owns mem via the chain
    const int n = BIO_read(b64.get(), out.data(), static_cast<int>(out.size()));
    if (n <= 0) return {};
    out.resize(static_cast<size_t>(n));
    return out;
}

// One verifier for the product, not two. This used to carry its own copy of the OpenSSL
// dance, which meant the licence path would not have learned about post-quantum signatures
// when the release path did — the two would have drifted silently, and the licence one is the
// harder of the two to notice going wrong.
bool signature_ok(const std::string& body, const std::vector<unsigned char>& sig) {
    return verify_release_signature(
        kLicensePubKey, body,
        std::string(reinterpret_cast<const char*>(sig.data()), sig.size()));
}

LicenseStatus invalid(const std::string& why) {
    LicenseStatus st;
    st.state   = LicenseState::Invalid;
    st.detail  = why;
    st.summary = "licence file rejected: " + why;
    return st;
}

std::string read_file(const std::string& path, bool& ok) {
    std::ifstream in(path, std::ios::binary);
    ok = static_cast<bool>(in);
    if (!ok) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

} // namespace

LicenseStatus license_from_text(const std::string& text, std::time_t now) {
    bool have_body = false, have_sig = false;
    const std::string body = between(text, kBodyBegin, kBodyEnd, have_body);
    const std::string sig  = between(text, kSigBegin,  kSigEnd,  have_sig);
    if (!have_body) return invalid("no BEGIN/END FASTPKI LICENSE block");
    if (!have_sig)  return invalid("no signature block");

    const std::vector<unsigned char> raw = b64_decode(sig);
    if (raw.empty())            return invalid("the signature is not valid base64");
    if (!signature_ok(body, raw))
        return invalid("the signature does not verify against the built-in FastPKI key");

    std::map<std::string, std::string> f;
    std::istringstream lines(body);
    for (std::string line; std::getline(lines, line); ) {
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        f[trim(line.substr(0, colon))] = trim(line.substr(colon + 1));
    }

    LicenseStatus st;
    st.number   = f["number"];
    st.customer = f["customer"];
    st.tier     = f["tier"];
    st.issued   = f["issued"];
    st.nodes    = f["nodes"];
    st.expires  = f["expires"];
    if (st.number.empty()) return invalid("the licence has no number");

    if (st.expires.empty()) {
        st.state     = LicenseState::Licensed;
        st.perpetual = true;
        st.summary   = "licensed: " + st.number +
                       (st.customer.empty() ? "" : " (" + st.customer + ")") + ", perpetual";
        return st;
    }
    if (!valid_iso_date(st.expires))
        return invalid("expires is not a date (expected YYYY-MM-DD, got '" + st.expires + "')");

    const std::string today = today_utc(now);
    st.state   = st.expires < today ? LicenseState::Expired : LicenseState::Licensed;
    st.summary = (st.state == LicenseState::Expired ? "licence expired: " : "licensed: ") +
                 st.number + (st.customer.empty() ? "" : " (" + st.customer + ")") +
                 (st.state == LicenseState::Expired ? ", expired " : ", expires ") + st.expires;
    return st;
}

LicenseStatus license_status(const Config& cfg, const std::string& eval_started, std::time_t now) {
    // A configured licence is the answer, whatever it says — including "this does not
    // verify". Falling back to the evaluation when a customer's licence is broken would hide
    // the breakage behind a state that looks fine for thirty days.
    //
    // Inline first: it is what the console's upload writes, so an operator who has just
    // uploaded one sees that one, not a stale file a previous admin left on the disk.
    if (!cfg.license_text.empty()) return license_from_text(cfg.license_text, now);
    if (!cfg.license_file.empty()) {
        bool ok = false;
        const std::string text = read_file(cfg.license_file, ok);
        if (!ok) return invalid("cannot read " + cfg.license_file);
        return license_from_text(text, now);
    }

    LicenseStatus st = license_from_text(kEvalLicense, now);
    if (st.state == LicenseState::Invalid) return st;   // a broken build; say so rather than lie

    const std::string started = valid_iso_date(eval_started) ? eval_started : today_utc(now);
    int days = 30;
    {   // the period is a field of the built-in licence, so the number lives in one place
        std::istringstream lines{std::string(kEvalLicense)};
        for (std::string line; std::getline(lines, line); ) {
            if (line.rfind("period_days:", 0) != 0) continue;
            try { days = std::stoi(trim(line.substr(12))); } catch (...) {}
            break;
        }
    }
    const std::string ends = date_plus_days(started, days);
    st.expires   = ends;
    st.perpetual = false;
    st.state     = (!ends.empty() && ends < today_utc(now)) ? LicenseState::EvaluationOver
                                                            : LicenseState::Evaluation;
    st.summary = st.state == LicenseState::EvaluationOver
        ? "evaluation ended on " + ends +
          " — non-commercial use stays free under PolyForm Noncommercial; "
          "a commercial deployment needs a licence"
        : "evaluation: " + std::to_string(days) + " days from " + started + ", ends " + ends;
    return st;
}

LicenseStatus license_status(const Config& cfg, const std::string& eval_started) {
    return license_status(cfg, eval_started, std::time(nullptr));
}

std::string license_eval_started(Db& db) {
    const std::string today = today_utc(std::time(nullptr));
    try {
        const auto kv = db.get_config();
        const auto it = kv.find("LICENSE_EVAL_STARTED");
        if (it != kv.end() && !it->second.empty()) return it->second;
    } catch (...) {
        return today;   // cannot read: report from today rather than fail
    }
    // ⚠️ THE WRITE IS BEST EFFORT AND NEVER FATAL. This runs at startup, and a node whose
    // PostgreSQL is a read-only standby cannot write. Letting that escape would crash-loop the
    // service on precisely the node an operator most needs to reach — which has already
    // happened here once, for a different startup write. The primary records the date and this
    // node reads it back through replication.
    try { db.set_config("LICENSE_EVAL_STARTED", today); }
    catch (const std::exception& e) {
        log::debug(std::string("license: could not record the evaluation start date "
                               "(the primary will): ") + e.what());
    }
    return today;
}

void log_license(const LicenseStatus& st) {
    const bool good = st.state == LicenseState::Licensed || st.state == LicenseState::Evaluation;
    if (good) log::info("license: " + st.summary);
    else      log::err("license: " + st.summary);
}

} // namespace pki
