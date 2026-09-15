#pragma once

#include <drogon/HttpController.h>

namespace tardis {
class Catalog;
}

class HomeController : public drogon::HttpController<HomeController> {
   public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(HomeController::index, "/", drogon::Get);
    ADD_METHOD_TO(HomeController::archive_url, "/archive/url", drogon::Get);
    ADD_METHOD_TO(HomeController::archive_history_url, "/archive/history/url", drogon::Get);
    ADD_METHOD_TO(HomeController::statistics, "/statistics", drogon::Get);
    ADD_METHOD_TO(HomeController::certificate_change, "/certificate_change", drogon::Get);
    ADD_METHOD_TO(HomeController::known_security_txt, "/known_security_txt", drogon::Get);
    ADD_METHOD_TO(HomeController::known_feeds, "/known_feeds", drogon::Get);
    ADD_METHOD_TO(HomeController::known_feeds_json, "/api/v1/known_feeds", drogon::Get);
    ADD_METHOD_TO(HomeController::about, "/about", drogon::Get);
    ADD_METHOD_TO(HomeController::doc_api, "/docs/api", drogon::Get);
    ADD_METHOD_TO(HomeController::robots, "/robots.txt", drogon::Get);
    METHOD_LIST_END

    static void configure(tardis::Catalog& catalog);

    void index(const drogon::HttpRequestPtr& request,
               std::function<void(const drogon::HttpResponsePtr&)>&& reply);
    void archive_url(const drogon::HttpRequestPtr& request,
                     std::function<void(const drogon::HttpResponsePtr&)>&& reply);
    void archive_history_url(const drogon::HttpRequestPtr& request,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply);
    drogon::Task<drogon::HttpResponsePtr> statistics(drogon::HttpRequestPtr request);
    drogon::Task<drogon::HttpResponsePtr> certificate_change(drogon::HttpRequestPtr request);
    drogon::Task<drogon::HttpResponsePtr> known_security_txt(drogon::HttpRequestPtr request);
    drogon::Task<drogon::HttpResponsePtr> known_feeds(drogon::HttpRequestPtr request);
    drogon::Task<drogon::HttpResponsePtr> known_feeds_json(drogon::HttpRequestPtr request);
    void about(const drogon::HttpRequestPtr& request,
                    std::function<void(const drogon::HttpResponsePtr&)>&& reply);
    void doc_api(const drogon::HttpRequestPtr& request,
                    std::function<void(const drogon::HttpResponsePtr&)>&& reply);
    void robots(const drogon::HttpRequestPtr& request,
                    std::function<void(const drogon::HttpResponsePtr&)>&& reply);

   private:
    static tardis::Catalog* catalog_;
};
