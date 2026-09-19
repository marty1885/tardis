cmake_minimum_required(VERSION 3.20)
project(tardis LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Drogon REQUIRED)
find_package(SQLite3 REQUIRED)
find_library(TARDIS_SQLITE3_LIBRARY NAMES sqlite3 REQUIRED)
find_library(ZSTD_LIBRARY zstd REQUIRED)
find_library(ARCHIVE_LIBRARY archive REQUIRED)
find_library(SODIUM_LIBRARY sodium REQUIRED)
find_library(CAP_LIBRARY cap REQUIRED)
find_library(SECCOMP_LIBRARY seccomp REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(pugixml CONFIG REQUIRED)

# Dremini is an upstream submodule with TARDIS's network-policy patch applied
# in its working tree. Keep the patch file under patches/dremini for review and
# for exporting upstream.
set(DREMINI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/dremini)
set(DREMINI_CLIENT_SOURCE ${DREMINI_DIR}/dremini/GeminiClient.cpp)

add_library(dremini STATIC ${DREMINI_CLIENT_SOURCE}
                           ${DREMINI_DIR}/dremini/GeminiParser.cpp
                           ${DREMINI_DIR}/dremini/GeminiServer.cpp
                           ${DREMINI_DIR}/dremini/Titan.cpp)
target_include_directories(dremini PUBLIC ${DREMINI_DIR})
target_link_libraries(dremini PUBLIC Drogon::Drogon OpenSSL::Crypto)

add_library(tlgs_url STATIC src/tlgs_url_parser.cpp src/tlgs_link_compose.cpp src/url_redirect.cpp)
target_include_directories(tlgs_url PUBLIC src)
target_link_libraries(tlgs_url PUBLIC Drogon::Drogon)

add_library(tardis_catalog STATIC src/catalog.cpp)
target_include_directories(tardis_catalog PUBLIC src)
target_link_libraries(tardis_catalog PUBLIC Drogon::Drogon)

add_library(tardis_api_clients STATIC src/api_client_store.cpp)
target_include_directories(tardis_api_clients PUBLIC src)
target_link_libraries(tardis_api_clients PUBLIC Drogon::Drogon OpenSSL::Crypto)

# Minijail is pinned to official upstream HEAD as a submodule. It provides the
# Landlock basis for TARDIS's optional post-bootstrap sandbox; generated
# sources live in the build tree so this repository needs no prior Minijail
# build step.
set(TARDIS_MINIJAIL_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/minijail")
set(TARDIS_MINIJAIL_CONSTANTS_SOURCE "${TARDIS_MINIJAIL_GENERATED_DIR}/libconstants.gen.c")
set(TARDIS_MINIJAIL_SYSCALLS_SOURCE "${TARDIS_MINIJAIL_GENERATED_DIR}/libsyscalls.gen.c")
add_custom_command(
    OUTPUT "${TARDIS_MINIJAIL_CONSTANTS_SOURCE}" "${TARDIS_MINIJAIL_SYSCALLS_SOURCE}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${TARDIS_MINIJAIL_GENERATED_DIR}"
    COMMAND ${CMAKE_COMMAND} -E env "CC=${CMAKE_C_COMPILER}"
            "${CMAKE_CURRENT_SOURCE_DIR}/third_party/minijail/gen_constants.sh"
            "${TARDIS_MINIJAIL_CONSTANTS_SOURCE}"
    COMMAND ${CMAKE_COMMAND} -E env "CC=${CMAKE_C_COMPILER}"
            "${CMAKE_CURRENT_SOURCE_DIR}/third_party/minijail/gen_syscalls.sh"
            "${TARDIS_MINIJAIL_SYSCALLS_SOURCE}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/third_party/minijail"
    DEPENDS third_party/minijail/Makefile third_party/minijail/gen_constants.c
            third_party/minijail/gen_constants-inl.h third_party/minijail/libconstants.h
            third_party/minijail/gen_constants.sh third_party/minijail/gen_syscalls.c
            third_party/minijail/gen_syscalls-inl.h third_party/minijail/libsyscalls.h
            third_party/minijail/gen_syscalls.sh
    VERBATIM)
add_library(tardis_minijail STATIC
    third_party/minijail/libminijail.c third_party/minijail/syscall_filter.c
    third_party/minijail/signal_handler.c third_party/minijail/bpf.c
    third_party/minijail/landlock_util.c third_party/minijail/util.c
    third_party/minijail/system.c third_party/minijail/syscall_wrapper.c
    third_party/minijail/config_parser.c "${TARDIS_MINIJAIL_CONSTANTS_SOURCE}"
    "${TARDIS_MINIJAIL_SYSCALLS_SOURCE}")
target_include_directories(tardis_minijail PUBLIC third_party/minijail)
target_compile_definitions(tardis_minijail PRIVATE PRELOADPATH="" BINDMOUNT_ALLOWED_PREFIXES="/dev,/sys")
target_link_libraries(tardis_minijail PUBLIC ${CAP_LIBRARY})
set_target_properties(tardis_minijail PROPERTIES C_STANDARD 17 C_EXTENSIONS ON)

add_library(tardis_fd_canaries STATIC src/fd_canaries.cpp)
target_include_directories(tardis_fd_canaries PUBLIC src)
target_link_libraries(tardis_fd_canaries PUBLIC Drogon::Drogon ${SODIUM_LIBRARY})

add_library(tardis_sandbox STATIC src/sandbox.cpp src/landlock_tsync_wrap.c)
target_include_directories(tardis_sandbox PUBLIC src third_party/minijail)
target_link_libraries(tardis_sandbox PUBLIC tardis_minijail ${SECCOMP_LIBRARY})
set_target_properties(tardis_sandbox PROPERTIES C_STANDARD 17 C_EXTENSIONS ON)

add_executable(tardis src/main.cpp src/home_controller.cpp src/archive_link_rewrite.cpp
                    src/object_store.cpp)
target_include_directories(tardis PRIVATE src)
target_link_libraries(tardis PRIVATE tardis_catalog tardis_api_clients dremini tlgs_url
                                         tardis_sandbox Drogon::Drogon ${TARDIS_SQLITE3_LIBRARY}
                                         ${SODIUM_LIBRARY} ${ZSTD_LIBRARY} ${ARCHIVE_LIBRARY})
target_link_options(tardis PRIVATE "LINKER:--wrap=landlock_create_ruleset"
                    "LINKER:--wrap=landlock_restrict_self")

add_executable(tardis-crawler src/crawler_main.cpp src/crawler.cpp src/exclusion.cpp
                              src/sqlite_step_profile.cpp
                              src/object_store.cpp src/ssrf.cpp)
target_include_directories(tardis-crawler PRIVATE src ${SQLite3_INCLUDE_DIRS})
target_link_libraries(tardis-crawler PRIVATE dremini tlgs_url Drogon::Drogon
                                             tardis_catalog tardis_sandbox ${SQLite3_LIBRARIES} ${ZSTD_LIBRARY}
                                             ${SODIUM_LIBRARY}
                                             OpenSSL::Crypto pugixml::pugixml ${CMAKE_DL_LIBS})
target_link_options(tardis-crawler PRIVATE "LINKER:--wrap=landlock_create_ruleset"
                    "LINKER:--wrap=landlock_restrict_self")

include(CTest)
if(BUILD_TESTING)
  add_executable(tardis_catalog_unit tests/catalog_test.cpp)
  target_link_libraries(tardis_catalog_unit PRIVATE tardis_catalog ${TARDIS_SQLITE3_LIBRARY})
  add_test(NAME tardis_catalog_unit COMMAND tardis_catalog_unit)

  add_executable(tardis_unit tests/unit.cpp src/crawler.cpp src/exclusion.cpp
                            src/archive_link_rewrite.cpp
                            src/object_store.cpp src/ssrf.cpp)
  target_include_directories(tardis_unit PRIVATE src ${SQLite3_INCLUDE_DIRS})
  target_link_libraries(tardis_unit PRIVATE dremini tlgs_url tardis_api_clients Drogon::Drogon ${SQLite3_LIBRARIES}
                                           tardis_catalog ${ZSTD_LIBRARY} ${SODIUM_LIBRARY}
                                           OpenSSL::Crypto pugixml::pugixml ${CMAKE_DL_LIBS})
  add_test(NAME tardis_unit COMMAND tardis_unit)
endif()
