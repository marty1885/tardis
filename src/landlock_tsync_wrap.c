/*
 * Inject newer Landlock protections into upstream Minijail without carrying a
 * Minijail patch.  The final executable wraps ruleset creation and enforcement
 * to add ABI-9 pathname UNIX socket mediation, abstract UNIX socket scoping,
 * and process-wide thread synchronization.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "landlock_util.h"

#ifndef LANDLOCK_RESTRICT_SELF_TSYNC
#define LANDLOCK_RESTRICT_SELF_TSYNC (1U << 3)
#endif

#ifndef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 16)
#endif

#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#endif

#define NORTHWIRE_LANDLOCK_ABI_UNIX_SOCKET_MEDIATION 9

struct northwire_landlock_ruleset_attr {
    __u64 handled_access_fs;
    __u64 handled_access_net;
    __u64 scoped;
};

static const char *allowed_unix_socket_directory;

void northwire_landlock_allow_unix_socket_directory(const char *path)
{
    allowed_unix_socket_directory = path;
}

int __real_landlock_create_ruleset(const void *attr, size_t size, __u32 flags);
int __real_landlock_restrict_self(int ruleset_fd, __u32 flags);

int __wrap_landlock_create_ruleset(
    const struct minijail_landlock_ruleset_attr *attr, size_t size, __u32 flags)
{
    if (attr == NULL || flags != 0)
        return __real_landlock_create_ruleset(attr, size, flags);
    const int abi = __real_landlock_create_ruleset(
        NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    // ABI 9 introduced pathname UNIX-socket mediation and the scope field.
    // Asking an ABI-8 kernel to handle either makes ruleset creation fail,
    // leaving Minijail with an invalid descriptor and no filesystem sandbox.
    // Retain Minijail's normal Landlock ruleset on older supported kernels.
    if (abi < NORTHWIRE_LANDLOCK_ABI_UNIX_SOCKET_MEDIATION)
        return __real_landlock_create_ruleset(attr, size, flags);
    if (size < sizeof(attr->handled_access_fs)) {
        errno = EINVAL;
        return -1;
    }

    struct northwire_landlock_ruleset_attr extended = {0};
    const size_t copied_size = size < sizeof(extended) ? size : sizeof(extended);
    memcpy(&extended, attr, copied_size);
    extended.handled_access_fs |= LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
    extended.scoped |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
    return __real_landlock_create_ruleset(&extended, sizeof(extended), flags);
}

int __wrap_landlock_restrict_self(int ruleset_fd, __u32 flags)
{
    const int abi = __real_landlock_create_ruleset(
        NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < NORTHWIRE_LANDLOCK_ABI_UNIX_SOCKET_MEDIATION)
        return __real_landlock_restrict_self(ruleset_fd, flags);

    if (allowed_unix_socket_directory != NULL) {
        const int directory_fd = open(allowed_unix_socket_directory, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (directory_fd < 0)
            return -1;
        const struct minijail_landlock_path_beneath_attr socket_rule = {
            .allowed_access = LANDLOCK_ACCESS_FS_RESOLVE_UNIX,
            .parent_fd = directory_fd,
        };
        const int rule_result = landlock_add_rule(
            ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &socket_rule, 0);
        const int rule_errno = errno;
        close(directory_fd);
        if (rule_result != 0) {
            errno = rule_errno;
            return -1;
        }
    }

    return __real_landlock_restrict_self(ruleset_fd, flags | LANDLOCK_RESTRICT_SELF_TSYNC);
}
