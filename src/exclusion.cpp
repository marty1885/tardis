#include "exclusion.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "crawler.hpp"

namespace tardis {
namespace {
bool starts(std::string_view value, std::string_view prefix) {
    return value.starts_with(prefix);
}
bool contains(std::string_view value, std::string_view needle) {
    return value.find(needle) != std::string_view::npos;
}
bool ends(std::string_view value, std::string_view suffix) {
    return value.ends_with(suffix);
}
bool git_route(std::string_view value) {
    static constexpr auto kRoutes = std::to_array<std::string_view>(
        {"commit", "commits", "tree", "blob", "blame", "log", "patch", "diff", "raw"});
    return std::find(kRoutes.begin(), kRoutes.end(), value) != kRoutes.end();
}
bool contains_git_route(std::string_view path) {
    size_t start = 0;
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto component =
            path.substr(start, end == std::string_view::npos ? path.size() - start : end - start);
        if (git_route(component))
            return true;
        if (end == std::string_view::npos)
            break;
        start = end + 1;
    }
    return false;
}
bool git_action(std::string_view params) {
    for (const auto route : {"commit", "commits", "tree", "blob", "blame", "log", "patch", "diff"})
        if (contains(params, std::string("a=") + route))
            return true;
    return false;
}
bool svn_route(std::string_view value) {
    static constexpr auto kRoutes = std::to_array<std::string_view>(
        {"svn", "svnroot", "viewvc", "viewcvs", "svnweb", "changeset", "trunk", "branches"});
    return std::find(kRoutes.begin(), kRoutes.end(), value) != kRoutes.end();
}
bool contains_svn_route(std::string_view path) {
    size_t start = 0;
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto component =
            path.substr(start, end == std::string_view::npos ? path.size() - start : end - start);
        if (svn_route(component))
            return true;
        if (end == std::string_view::npos)
            break;
        start = end + 1;
    }
    return false;
}
bool svn_action(std::string_view params) {
    return contains(params, "pathrev=") || contains(params, "peg=");
}
std::string lower(std::string value) {
    for (auto& character : value)
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    return value;
}

// Ported from TLGS's crawler blacklist.  Prefixes are canonical Gemini URLs;
// a matching prefix excludes the whole resource subtree.
constexpr auto kHosts =
    std::to_array<std::string_view>({"example.com", "example.org", "example.net", "example.io",
                                     "example.us", "example.eu", "example.gov", "example.space"});
constexpr auto kDeadHosts = std::to_array<std::string_view>(
    {"gus.guru", "ftrv.se", "git.thebackupbox.net", "mikelynch.org", "campaignwiki.org"});
// Do not spell the length separately: an over-sized std::array is padded with
// empty string_views, which would accidentally match every URL.
constexpr auto kPrefixes =
    std::to_array<std::string_view>({"gemini://www.youtube.com/",
                                     "gemini://tictactoe.lanterne.chilliet.eu",
                                     "gemini://mirrors.apple2.org.za/active/",
                                     "gemini://mirrors.apple2.org.za/archive/",
                                     "gemini://kamalatta.ddnss.de/",
                                     "gemini://tweek.zyxxyz.eu/valentina/",
                                     "gemini://ansi.hrtk.in/",
                                     "gemini://matrix.kiwifarms.net",
                                     "gemini://songs.zachdecook.com/song.gmi.php/",
                                     "gemini://songs.zachdecook.com/chord.svg/",
                                     "gemini://gemini.zachdecook.com/cgi-bin/ccel.sh",
                                     "gemini://cadence.moe/chapo/",
                                     "gemini://nixo.xyz/reply/",
                                     "gemini://nixo.xyz/notify",
                                     "gemini://gemini.thebackupbox.net/queryresponse",
                                     "gemini://gem.garichankar.com/share_audio",
                                     "gemini://vps01.rdelaage.ovh/",
                                     "gemini://mastogem.picasoft.net",
                                     "gemini://runjimmyrunrunyoufuckerrun.com/fonts/",
                                     "gemini://runjimmyrunrunyoufuckerrun.com/tmp/",
                                     "gemini://houston.coder.town/search?",
                                     "gemini://houston.coder.town/search/",
                                     "gemini://marginalia.nu/search",
                                     "gemini://kennedy.gemi.dev/cached?",
                                     "gemini://kennedy.gemi.dev/archive/",
                                     "gemini://g.619.hu/repo.gmi",
                                     "gemini://gem.snork.ca/textfiles.com/",
                                     "gemini://gem.snork.ca/rfc-editor.org/",
                                     "gemini://uc.cthulhu28.space/v16/",
                                     "gemini://gemini.autonomy.earth/current_month/archive/",
                                     "gemini://gemhoo.zone/mirrors/textfiles/",
                                     "gemini://r13.xyz/games/bell-below/",
                                     "gemini://kennedy.gemi.dev/observatory/",
                                     "gemini://kennedy.gemi.dev/page-info?",
                                     "gemini://kennedy.gemi.dev/reports/",
                                     "gemini://geddit.pitr.ca/post?",
                                     "gemini://geddit.pitr.ca/c/",
                                     "gemini://geddit.glv.one/post?",
                                     "gemini://geddit.glv.one/c/",
                                     "gemini://gemini.marmaladefoo.com/cgi-bin/calc.cgi?",
                                     "gemini://gemini.circumlunar.space/users/fgaz/calculator/",
                                     "gemini://acidic.website/cgi-bin/weather.tcl?",
                                     "gemini://caolan.uk/weather/",
                                     "gemini://alexschroeder.ch/",
                                     "gemini://mozz.us/files/gemini-links.gmi",
                                     "gemini://gem.benscraft.info/mailing-list",
                                     "gemini://rawtext.club/~sloum/geminilist",
                                     "gemini://gemini.techrights.org/",
                                     "gemini://pon.ix.tc/cgi-bin/youtube.cgi?",
                                     "gemini://pon.ix.tc/youtube/",
                                     "gemini://taz.de/",
                                     "gemini://simplynews.metalune.xyz",
                                     "gemini://illegaldrugs.net/cgi-bin/news.php?",
                                     "gemini://illegaldrugs.net/cgi-bin/reader",
                                     "gemini://rawtext.club/~sloum/geminews",
                                     "gemini://gemini.cabestan.tk/hn",
                                     "gemini://hn.filiuspatris.net/",
                                     "gemini://schmittstefan.de/de/nachrichten/",
                                     "gemini://gmi.noulin.net/mobile",
                                     "gemini://jpfox.fr/rss/",
                                     "gemini://illegaldrugs.net/cgi-bin/news.php/",
                                     "gemini://dw.schettler.net/",
                                     "gemini://dioskouroi.xyz/top",
                                     "gemini://drewdevault.com/cgi-bin/hn.py",
                                     "gemini://tobykurien.com/maverick/",
                                     "gemini://gemini.knusbaum.com",
                                     "gemini://wp.pitr.ca/",
                                     "gemini://wp.glv.one/",
                                     "gemini://wikipedia.geminet.org/",
                                     "gemini://wikipedia.geminet.org:1966",
                                     "gemini://vault.transjovian.org/",
                                     "gemini://egsam.pitr.ca/",
                                     "gemini://egsam.glv.one/",
                                     "gemini://gemini.conman.org/test",
                                     "gemini://chat.mozz.us/stream",
                                     "gemini://chat.mozz.us/submit",
                                     "gemini://80h.dev/agena/",
                                     "gemini://astrobotany.mozz.us/app/",
                                     "gemini://carboncopy.xyz/cgi-bin/apache.gex/",
                                     "gemini://gemini.susa.net/cgi-bin/search?",
                                     "gemini://gemini.susa.net/cgi-bin/twitter?",
                                     "gemini://gemini.susa.net/cgi-bin/vim-search?",
                                     "gemini://gemini.susa.net/cgi-bin/links_stu.lua?",
                                     "gemini://gemini.spam.works/textfiles/",
                                     "gemini://gemini.spam.works/mirrors/textfiles/",
                                     "gemini://gemini.spam.works/users/dvn/archive/",
                                     "gemini://gemini.thebackupbox.net/radio",
                                     "gemini://higeki.jp/radio",
                                     "gemini://drewdevault.com/cgi-bin/web.sh?",
                                     "gemini://gemiprox.pollux.casa/",
                                     "gemini://gemiprox.pollux.casa:1966",
                                     "gemini://ecs.d2evs.net/proxy/",
                                     "gemini://gmi.si3t.ch/www-gem/",
                                     "gemini://orrg.clttr.info/orrg.pl",
                                     "gemini://mysidard.com/services/hackernews/",
                                     "gemini://gem.denarii.cloud/",
                                     "gemini://cfdocs.wetterberg.nu/",
                                     "gemini://godocs.io",
                                     "gemini://emacswiki.org/",
                                     "gemini://si3t.ch/code/",
                                     "gemini://tilde.club/~filip/library/",
                                     "gemini://gemini.bortzmeyer.org/rfc-mirror/",
                                     "gemini://chris.vittal.dev/rfcs",
                                     "gemini://going-flying.com/git/cgi/gemini.git/",
                                     "gemini://szczezuja.flounder.online/git/",
                                     "gemini://gmi.noulin.net/rfc",
                                     "gemini://gmi.noulin.net/man",
                                     "gemini://hellomouse.net/user-pages/handicraftsman/ietf/",
                                     "gemini://tilde.team/~orichalcumcosmonaut/darcs/website/prod/",
                                     "gemini://gemini.omarpolo.com/cgi",
                                     "gemini://gemini.rmf-dev.com",
                                     "gemini://musicbrainz.uploadedlobster.com/",
                                     "gemini://gemini.lost-frequencies.eu/posts/archive",
                                     "gemini://blitter.com/",
                                     "gemini://ake.crabdance.com:1966/message/",
                                     "gemini://iceworks.cc/z/",
                                     "gemini://ake.crabdance.com:1966/channel/",
                                     "gemini://gemini.autonomy.earth/posts/",
                                     "gemini://lists.flounder.online/gemini/threads/messages/",
                                     "gemini://tilde.pink/~bencollver/gamefaqs/",
                                     "gemini://tilde.pink/~bencollver/gamefaq/",
                                     "gemini://gemini.quux.org/0/Archives",
                                     "gemini://gemini.rob-bolton.co.uk/songs",
                                     "gemini://gthudson.xyz/cgi-bin/quietplace.cgi",
                                     "gemini://futagoza.gamiri.com/gmninkle/",
                                     "gemini://alexey.shpakovsky.ru/maze",
                                     "gemini://jsreed5.org/live/cgi-bin/twisty/",
                                     "gemini://gemini.theuse.net/",
                                     "gemini://202x.moe/resonance",
                                     "gemini://gmi.skyjake.fi/",
                                     "gemini://warmedal.se/.well-known/",
                                     "gemini://www.bonequest.com/",
                                     "gemini://kennedy.gemi.dev/page-info?id=",
                                     "gemini://gemi.dev/xkcd",
                                     "gemini://gemi.dev/cgi-bin/",
                                     "gemini://gemlog.stargrave.org/",
                                     "gemini://jsreed5.org/oeis/"});
}  // namespace

bool excluded_by_policy(const Url& url, std::string_view* reason) {
    auto reject = [reason](std::string_view value) {
        if (reason)
            *reason = value;
        return true;
    };
    if (url.port(1965) == 443)
        return reject("port-443");
    if (url.host() == "localhost" || url.host() == "localhost.localdomain" ||
        url.host() == "[::1]" || starts(url.host(), "127.0.0.") || ends(url.host(), ".local") ||
        ends(url.host(), ".localhost") || ends(url.host(), ".localdomain"))
        return reject("local-address");
    if (ends(url.host(), ".onion"))
        return reject("hidden-service");
    if (std::find(kHosts.begin(), kHosts.end(), url.host()) != kHosts.end() ||
        std::find(kDeadHosts.begin(), kDeadHosts.end(), url.host()) != kDeadHosts.end())
        return reject("host");
    const auto text = url.str();
    if (std::any_of(kPrefixes.begin(), kPrefixes.end(),
                    [&](auto prefix) { return starts(text, prefix); }))
        return reject("known-unbounded-or-mirror");
    if (starts(url.path(), "/git/") || starts(url.host(), "git.") || contains(text, ".git/") ||
        contains_git_route(url.path()) || git_action(url.param()) || ends(text, "/git.sh"))
        return reject("git");
    if (contains(text, "/.svn/") || contains_svn_route(url.path()) || svn_action(url.param()))
        return reject("svn");
    if (contains(text, "/~xkcd/") || contains(text, "/xkcd/"))
        return reject("xkcd-archive");
    const auto path = lower(std::string(url.path()));
    // This CGI maze appends its state to its own query string on each link.
    // The resulting route has an unbounded URL space, so do not admit any
    // query variant to the crawl frontier.
    if (url.host() == "gem.pwarren.id.au" && path == "/cgi-bin/maze.cgi")
        return reject("maze-generator");
    // Archive cached views encode historic captures in the query string. They
    // commonly rewrite every link to another cached view, creating an
    // unbounded history crawl. This is intentionally host-agnostic:
    // */archive/cached?*.
    if (ends(path, "/archive/cached") && !url.param().empty())
        return reject("archive-cached-view");
    // Test CGI/Python handlers commonly expose an unbounded state space via
    // query parameters (for example test_gemcgi.py?moves=...).
    if (path.find("test_") != std::string::npos &&
        (path.find(".py") != std::string::npos || path.find(".cgi") != std::string::npos))
        return reject("test-script");
    // Gemski game-state URLs generate a new state on each move and do not
    // describe a finite set of capsule documents. Exclude both spellings of
    // the route before they can enter the frontier.
    if (path.starts_with("/gemski/play") || path.starts_with("/ski/play"))
        return reject("gemski-generator");
    // Countdown pages encode each tick in the query string; the directory is
    // a generator rather than a finite set of capsule documents.
    if (url.host() == "sava.rocks" && path.starts_with("/fun-stuff/") &&
        path.find("-countdown/") != std::string::npos)
        return reject("countdown-generator");
    // Search result URLs are generated from user input. Keep a static search
    // landing page eligible, but do not turn its query space into a frontier.
    if ((path == "/search" || path == "/search/") && !url.param().empty())
        return reject("search-query");
    if (ends(url.path(), "/next.cgi") || ends(url.path(), "/prev.cgi") ||
        ends(url.path(), "/rand.cgi") || ends(url.path(), "/next") || ends(url.path(), "/prev") ||
        ends(url.path(), "/rand") || ends(url.path(), "/next.gmi") ||
        ends(url.path(), "/prev.gmi") || ends(url.path(), "/rand.gmi"))
        return reject("webring-navigation");
    if (contains(text, "gopher:/:/") || contains(text, "rfc-mirror"))
        return reject("proxy-or-mirror");
    if (std::any_of(text.begin(), text.end(), [](unsigned char c) { return c < 32; }))
        return reject("control-character");
    std::unordered_map<std::string, size_t> components;
    for (const auto& component : std::filesystem::path(url.path()))
        if (++components[component.generic_string()] >= 3)
            return reject("repeated-path-component");
    const auto commit = text.find("commits/");
    if (commit != std::string::npos) {
        const auto tail = text.substr(commit + 8);
        const auto slash = tail.find('/');
        if (slash != std::string::npos && slash + 1 < tail.size() &&
            std::all_of(tail.begin(), tail.begin() + static_cast<long>(slash),
                        [](unsigned char c) { return std::isalnum(c); }))
            return reject("commit-history");
    }
    return false;
}

}  // namespace tardis
