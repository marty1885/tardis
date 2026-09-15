#include <TFile.h>
#include <TKey.h>
#include <TTree.h>

#include <cassert>
#include <filesystem>

#include "crawler.hpp"
#include "archive_link_rewrite.hpp"
#include "exclusion.hpp"
#include "format.hpp"
#include "media_type.hpp"
#include "root_body_store.hpp"
#include "ssrf.hpp"
#include "url_redirect.hpp"

int main() {
    using tardis::Crawler;
    using tardis::AutomaticTarget;
    assert(tardis::format_iec_bytes(0) == "0 bytes");
    assert(tardis::format_iec_bytes(1024) == "1.00 KiB");
    assert(tardis::format_iec_bytes(79347843) == "75.67 MiB");
    const auto gemini_mime = tardis::MediaType::parse(
        " Text/Gemini ; charset=\"utf-8\" ; lang=en ");
    assert(gemini_mime && gemini_mime->is("text", "gemini"));
    assert(!tardis::MediaType::parse("text/gemini; charset").has_value());
    assert(!tardis::MediaType::parse("text/gemini; charset=\"unterminated").has_value());
    assert(!tardis::is_public_network_address("127.0.0.1"));
    assert(!tardis::is_public_network_address("10.20.30.40"));
    assert(!tardis::is_public_network_address("100.64.1.2"));
    assert(!tardis::is_public_network_address("169.254.169.254"));
    assert(!tardis::is_public_network_address("172.31.0.1"));
    assert(!tardis::is_public_network_address("192.168.1.1"));
    assert(!tardis::is_public_network_address("198.18.0.1"));
    assert(!tardis::is_public_network_address("224.0.0.1"));
    assert(tardis::is_public_network_address("1.1.1.1"));
    assert(tardis::is_public_network_address("93.184.216.34"));
    assert(!tardis::is_public_network_address("::"));
    assert(!tardis::is_public_network_address("::1"));
    assert(!tardis::is_public_network_address("::ffff:127.0.0.1"));
    assert(!tardis::is_public_network_address("fe80::1"));
    assert(!tardis::is_public_network_address("fd00::1"));
    assert(!tardis::is_public_network_address("2001:db8::1"));
    assert(!tardis::is_public_network_address("2002:7f00:1::"));
    assert(tardis::is_public_network_address("2606:4700:4700::1111"));
    assert(!tardis::is_public_network_address("not-an-address"));
    auto url = tardis::Url::parse("gemini://Example.org:1965/a/../notes?q=x#part");
    assert(url && url->str() == "gemini://example.org/notes?q=x");
    auto relative = tardis::Url::resolve(*url, "today.gmi#heading");
    assert(relative && relative->str() == "gemini://example.org/today.gmi");
    assert(!tardis::Url::resolve(*url, "bad\r\n gemini://example.org/"));
    assert(!tardis::Url::resolve(*url, std::string("bad\0suffix", 10)));
    auto directory = tardis::Url::parse("gemini://gemini.ctrl-c.club/~julian/");
    assert(directory && directory->str() == "gemini://gemini.ctrl-c.club/~julian/");
    tlgs::Url yesterweb{"gemini://alice.cities.yesterweb.org/sites/example/"};
    tardis::redirect_internal_url(yesterweb);
    assert(yesterweb.str() == "gemini://cities.yesterweb.org/sites/example/");
    tlgs::Url tuxmachines{"gemini://tuxmachines.org/news.gmi"};
    tardis::redirect_internal_url(tuxmachines);
    assert(tuxmachines.str() == "gemini://gemini.tuxmachines.org/news.gmi");
    auto rules = Crawler::robots_rules(
        "User-agent: researcher\nDisallow: "
        "/private\n\nUser-agent: *\nDisallow: /tmp");
    assert(Crawler::path_blocked("/private/a", rules));
    assert(Crawler::path_blocked("/tmp/a", rules));
    assert(!Crawler::path_blocked("/public", rules));

    const auto virtual_source =
        "User-agent: *\nDisallow: /all\n\n"
        "User-agent: indexer\nDisallow: /index\n\n"
        "User-agent: tlgs\nDisallow: /legacy\n\n"
        "User-agent: tardis\nDisallow: /native\n\n"
        "User-agent: archiver\nDisallow: /archive\n\n"
        "User-agent: webproxy\nDisallow: /proxy\n";
    const auto legacy_rules = Crawler::robots_rules(virtual_source, tardis::Use::tlgs);
    assert(Crawler::path_blocked("/all", legacy_rules));
    assert(Crawler::path_blocked("/index", legacy_rules));
    assert(Crawler::path_blocked("/legacy", legacy_rules));
    assert(!Crawler::path_blocked("/native", legacy_rules));
    const auto archive_rules = Crawler::robots_rules(virtual_source, tardis::Use::archiver);
    assert(Crawler::path_blocked("/all", archive_rules));
    assert(Crawler::path_blocked("/native", archive_rules));
    assert(Crawler::path_blocked("/archive", archive_rules));
    assert(!Crawler::path_blocked("/legacy", archive_rules));
    const auto proxy_rules = Crawler::robots_rules(virtual_source, tardis::Use::webproxy);
    assert(Crawler::path_blocked("/proxy", proxy_rules));
    assert(Crawler::path_blocked("/archive/2026/private", {{false, "/archive/*/private$"}}));
    assert(!Crawler::path_blocked("/archive/2026/private/more", {{false, "/archive/*/private$"}}));
    assert(Crawler::path_blocked("/literal.+?/child", {{false, "/literal.+?"}}));
    assert(!Crawler::path_blocked("/literalXYZ/child", {{false, "/literal.+?"}}));
    auto northwire = Crawler::robots_rules(
        "User-agent: *\nDisallow: /\nAllow: /$\nAllow: /about\nAllow: /canary\n"
        "Allow: /about/encryption\nAllow: /privacy");
    assert(!Crawler::path_blocked("/", northwire));
    assert(!Crawler::path_blocked("/about", northwire));
    assert(!Crawler::path_blocked("/about/encryption", northwire));
    assert(!Crawler::path_blocked("/privacy", northwire));
    assert(Crawler::path_blocked("/elsewhere", northwire));

    // A cache miss and a cache hit both call robots_permissions(). Keep the
    // policy decision independent of where the source came from.
    assert(Crawler::robots_permissions("/anything", "") == 0x1f);

    const auto capsule_home = tardis::Url::parse("gemini://example.org/");
    const auto user_home = tardis::Url::parse("gemini://example.org/~marty");
    const auto deep_page = tardis::Url::parse("gemini://example.org/~marty/posts/1");
    assert(capsule_home && Crawler::gemini_homepage_kind(*capsule_home) ==
                               AutomaticTarget::homepage);
    assert(user_home && Crawler::gemini_homepage_kind(*user_home) ==
                            AutomaticTarget::homepage);
    assert(deep_page && Crawler::gemini_homepage_kind(*deep_page) ==
                            AutomaticTarget::none);
    const auto security_txt = tardis::Url::parse("gemini://example.org/.well-known/security.txt");
    assert(security_txt && Crawler::is_security_txt(*security_txt));
    assert(Crawler::robots_permissions("/anything", "User-agent: *\nDisallow: /\n") == 0);
    assert(Crawler::robots_permissions("/public", "User-agent: *\nDisallow: /private\n") ==
           0x1f);
    const auto split_permissions = Crawler::robots_permissions(
        "/native", "User-agent: *\nDisallow: /all\n\nUser-agent: tardis\nDisallow: /native\n");
    assert((split_permissions & static_cast<std::uint16_t>(tardis::Use::indexer)) == 0);
    assert((split_permissions & static_cast<std::uint16_t>(tardis::Use::archiver)) == 0);
    assert((split_permissions & static_cast<std::uint16_t>(tardis::Use::researcher)) == 0);
    assert((split_permissions & static_cast<std::uint16_t>(tardis::Use::webproxy)) == 0);
    assert((split_permissions & static_cast<std::uint16_t>(tardis::Use::tlgs)) != 0);

    std::string_view exclusion;
    auto git = tardis::Url::parse("gemini://capsule.example/git/project/tree/main/readme.gmi");
    assert(git && tardis::excluded_by_policy(*git, &exclusion) && exclusion == "git");
    auto git_tree =
        tardis::Url::parse("gemini://capsule.example/~alice/project/tree/2f4d8a1/readme.gmi");
    assert(git_tree && tardis::excluded_by_policy(*git_tree, &exclusion) && exclusion == "git");
    auto git_commit = tardis::Url::parse("gemini://capsule.example/project/commit/2f4d8a1");
    assert(git_commit && tardis::excluded_by_policy(*git_commit, &exclusion) && exclusion == "git");
    auto bare_git_repo = tardis::Url::parse("gemini://capsule.example/bookmark-sh.git/refs/main");
    assert(bare_git_repo && tardis::excluded_by_policy(*bare_git_repo, &exclusion) &&
           exclusion == "git");
    auto gitweb = tardis::Url::parse("gemini://capsule.example/gitweb?a=tree;h=2f4d8a1");
    assert(gitweb && tardis::excluded_by_policy(*gitweb, &exclusion) && exclusion == "git");
    auto svn = tardis::Url::parse("gemini://capsule.example/viewvc/project/trunk/readme.gmi");
    assert(svn && tardis::excluded_by_policy(*svn, &exclusion) && exclusion == "svn");
    auto ordinary_tags = tardis::Url::parse("gemini://capsule.example/posts/tags/gemini.gmi");
    assert(ordinary_tags && !tardis::excluded_by_policy(*ordinary_tags));
    auto ordinary_browser =
        tardis::Url::parse("gemini://capsule.example/browser-notes.gmi?revision=2");
    assert(ordinary_browser && !tardis::excluded_by_policy(*ordinary_browser));
    auto archive = tardis::Url::parse("gemini://gemlog.stargrave.org/huge/page.gmi");
    assert(archive && tardis::excluded_by_policy(*archive));
    auto ordinary = tardis::Url::parse("gemini://capsule.example/notes/today.gmi");
    assert(ordinary && !tardis::excluded_by_policy(*ordinary));
    auto cosmos = tardis::Url::parse("gemini://cosmos.skyjake.fi/");
    assert(cosmos && !tardis::excluded_by_policy(*cosmos));
    auto apple_archive = tardis::Url::parse("gemini://mirrors.apple2.org.za/active/4am/");
    assert(apple_archive && tardis::excluded_by_policy(*apple_archive, &exclusion) &&
           exclusion == "known-unbounded-or-mirror");
    auto search_query = tardis::Url::parse("gemini://sava.rocks/search/?debian");
    assert(search_query && tardis::excluded_by_policy(*search_query, &exclusion) &&
           exclusion == "search-query");
    auto search_landing = tardis::Url::parse("gemini://sava.rocks/search/");
    assert(search_landing && !tardis::excluded_by_policy(*search_landing));
    auto test_cgi = tardis::Url::parse("gemini://capsule.example/cgi-bin/test_gemcgi.py?moves=310");
    assert(test_cgi && tardis::excluded_by_policy(*test_cgi, &exclusion) &&
           exclusion == "test-script");
    auto countdown = tardis::Url::parse("gemini://sava.rocks/fun-stuff/new-year-countdown/?3815");
    assert(countdown && tardis::excluded_by_policy(*countdown, &exclusion) &&
           exclusion == "countdown-generator");
    auto gemski =
        tardis::Url::parse("gemini://gemini.thegonz.net/gemski/play:(%22state%22,1,0,80)");
    assert(gemski && tardis::excluded_by_policy(*gemski, &exclusion) &&
           exclusion == "gemski-generator");
    auto ski = tardis::Url::parse("gemini://gemini.thegonz.net/ski/play:(%22state%22,1,0,80)");
    assert(ski && tardis::excluded_by_policy(*ski, &exclusion) && exclusion == "gemski-generator");

    const auto rewritten_gemtext = tardis::rewrite_archived_gemtext_links(
        "=> next.gmi Next\n=> /root?q=x Root\n=> gemini://other.example/a External\n"
        "=> https://example.org/ Web\n```\n=> untouched.gmi\n```\n",
        "gemini://example.org/notes/today.gmi");
    assert(rewritten_gemtext ==
           "=> /archive/gemini/x/example.org%2Fnotes%2Fnext.gmi Next\n"
           "=> /archive/gemini/x/example.org%2Froot/param/q%3Dx Root\n"
           "=> /archive/gemini/x/other.example%2Fa External\n"
           "=> https://example.org/ Web\n```\n=> untouched.gmi\n```\n");

    const auto snapshot = std::filesystem::temp_directory_path() / "tardis-root-store-unit";
    std::filesystem::remove_all(snapshot);
    std::filesystem::create_directories(snapshot);
    const std::string raw = "tiny Gemini body";
    tardis::Hash256 digest;
    digest.fill(std::byte{0x2a});
    {
        tardis::RootBodyStore store(snapshot, "bodies/test.root", 7);
        store.put(digest, raw);
        const auto locations = store.checkpoint();
        assert(locations.size() == 1);
        assert(locations[0].blake2b_256 == digest);
        assert(locations[0].root_shard_id == 7);
        assert(locations[0].root_entry_index == 0);
        assert(store.entry_count() == 1);
        store.close();
    }
    const std::string second_raw = "body from a later crawler run";
    tardis::Hash256 second_digest;
    second_digest.fill(std::byte{0x2b});
    {
        // Normal process shutdown closes the file but does not seal a shard.
        // The next run resumes at the catalog's published entry count.
        tardis::RootBodyStore store(snapshot, "bodies/test.root", 7, 1);
        store.put(second_digest, second_raw);
        const auto locations = store.checkpoint();
        assert(locations.size() == 1 && locations[0].root_entry_index == 1);
        assert(store.entry_count() == 2);
        assert(store.storage_bytes() > 0);
        store.close();
    }
    std::unique_ptr<TFile> file(TFile::Open((snapshot / "bodies/test.root").c_str(), "READ"));
    assert(file && !file->IsZombie());
    int body_tree_keys = 0;
    TIter next_key(file->GetListOfKeys());
    while (const auto* key = dynamic_cast<TKey*>(next_key()))
        if (std::string_view(key->GetName()) == "bodies")
            ++body_tree_keys;
    assert(body_tree_keys == 1);
    auto* tree = file->Get<TTree>("bodies");
    assert(tree);
    assert(tree->GetEntries() == 2);
    std::array<unsigned char, 32> stored_digest{};
    std::vector<unsigned char>* stored = nullptr;
    tree->SetBranchAddress("blake2b_256", stored_digest.data());
    tree->SetBranchAddress("body", &stored);
    assert(tree->GetEntry(0) > 0);
    for (const auto byte : stored_digest) assert(byte == 0x2a);
    assert(std::string(stored->begin(), stored->end()) == raw);
    assert(tree->GetEntry(1) > 0);
    for (const auto byte : stored_digest) assert(byte == 0x2b);
    assert(std::string(stored->begin(), stored->end()) == second_raw);
    std::filesystem::remove_all(snapshot);
}
