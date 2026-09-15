// Vendored from TLGS tlgsutils/utils.cpp.
#include "tlgs_link_compose.hpp"

#include <cassert>
#include <filesystem>

tlgs::Url tlgs::linkCompose(const tlgs::Url& url, const std::string& path) {
    assert(path.size() != 0);
    tlgs::Url link_url;
    if (path[0] == '/') {
        tlgs::Url dummy = tlgs::Url("gemini://localhost" + path);
        link_url = tlgs::Url(url)
                       .withPath(dummy.path())
                       .withParam(dummy.param())
                       .withFragment(dummy.fragment());
    } else {
        tlgs::Url dummy = tlgs::Url("gemini://localhost/" + path, false);
        auto link_path = std::filesystem::path(dummy.path().substr(1));
        auto current_path = std::filesystem::path(url.path());
        if (url.path().back() == '/')
            link_url = tlgs::Url(url).withPath((current_path / link_path).generic_string());
        else
            link_url =
                tlgs::Url(url).withPath((current_path.parent_path() / link_path).generic_string());
        link_url.withParam(dummy.param()).withFragment(dummy.fragment());
    }
    return link_url;
}
