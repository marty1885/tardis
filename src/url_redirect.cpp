#include "url_redirect.hpp"

namespace tardis {

void redirect_internal_url(tlgs::Url& url) {
    constexpr std::string_view yesterweb = ".cities.yesterweb.org";
    if (url.port(1965) == 1965 && url.host().ends_with(yesterweb) &&
        url.host() != "cities.yesterweb.org" && url.path().starts_with("/sites/"))
        url.withHost("cities.yesterweb.org");
    if (url.port(1965) == 1965 && url.host() == "tuxmachines.org")
        url.withHost("gemini.tuxmachines.org");
}

}  // namespace tardis
