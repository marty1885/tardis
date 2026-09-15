# TARDIS crawler

The retrieval, updates, and feed endpoints are documented at the Gemini
`/docs/api` page. Build and run `tardis` against the same snapshot.

TARDIS is a persistent Gemini crawler and archiver. The crawler consumes the
typed catalog API; it does not issue SQL or maintain a second frontier model.

```sh
cmake -S . -B build
cmake --build build --parallel
./build/tardis-crawler --snapshot data gemini://example.org/
```

Supplying a URL as a positional argument submits it to `crawl_queue`. Existing
queued work can be resumed without supplying another seed:

```sh
./build/tardis-crawler --snapshot data
```

Use `--persistent` to keep the process alive after the queue is clean. It will
wait for scheduled watched pages and stop on a signal. Combine it with
`--watch` for unattended recurring crawling:

```sh
./build/tardis-crawler --snapshot data --persistent \
  --watch gemini://example.org/
```

Add a recurring page with `--watch`. Watched pages default to a seven-day
interval with plus or minus twelve hours of jitter. The calculated next time is
persisted in `watched_pages.next_enqueue_unix_millis`, so restarts do not
recreate a synchronized wave.

```sh
./build/tardis-crawler --snapshot data --watch gemini://example.org/ \
  --watch-interval 604800 --watch-jitter 43200
```

Use `--unwatch gemini://example.org/` to remove it from the recurring set.

## Automatic primary targets

Automatic recrawling is deliberately limited to primary update surfaces: a
successful `gemini://host/`, a successful `gemini://host/~user/`, a Gemini page
recognized as Gemsub, a valid `application/atom+xml` Atom feed, and an
`application/rss+xml` RSS feed, and a text-like `/twtxt.txt` TWTXT resource.
RSS and TWTXT are recognized without parsing. These are
stored separately from operator watches and are revisited using the same
interval and jitter controls. Any Gemini `5x` response removes that page from
automatic recrawling; successful captures that cease to be a feed also remove
their feed classification. Deep discovered pages remain one-shot.

Known current feeds are available to authenticated API clients at
`/api/v1/known-feeds/{mode}`. Add `?atom`, `?gemsub`, `?rss`, or `?twtxt` to
select one type; the default returns all feeds eligible for that API mode's
robots identity.

The public `/api/v1/known_feeds` endpoint uses archiver-visible feeds.
`?atom`, `?gemsub`, `?rss`, and `?twtxt` return a JSON array of URL strings;
an unknown or missing type returns Gemini 59 or HTTP 400.

Every crawled or discovered Gemini authority also receives a durable periodic
check of `/.well-known/security.txt`, including authorities that have never
served one. A `5x`, missing file, or non-`text/plain` response removes it from
the current shared list but does not stop future checks. Successful files are
available to authenticated clients at `/api/v1/known-security-txt/{mode}`.

The crawler performs these operations through `Catalog`:

- atomically claims a ready queue row and reserves its authority's politeness
  window;
- evaluates one cached `/robots.txt` for `tlgs`, `indexer`, `archiver`,
  `researcher`, and `webproxy`;
- fetches a page once when at least one virtual identity is eligible;
- flushes new bodies to ROOT and then atomically publishes object locators,
  crawl history, discovered queue rows, and completion of the claimed row;
- restores abandoned claims when reopening a snapshot;
- records transport failures as historical results and schedules explicit retry
  queue entries with host-wide backoff.

Redirect responses are archived against the requested page and their targets
are submitted to the queue. A redirect is therefore another explicit page
request rather than an invisible request made outside queue ownership.

## Archive representation

Every successful 2x body below or equal to 4 MiB is archived regardless of
MIME. Binary data is stored without interpretation; `text/gemini` is also
parsed for discovery. A body crossing the limit is recorded as `BodyTooLarge`
and its partial bytes are not published.

`robots.txt` has a separate 64 KiB ceiling. Oversized or failed robots policy
responses fail closed and enter the normal retry path rather than being stored
as unbounded catalog metadata. A completed robots response with no usable policy
(for example, a missing robots document) is cached as an empty allow-all policy;
transport failure is recorded as `NetworkFailure` and does not complete the page.

Bodies and certificates use BLAKE2b-256. Digests occupy 32-byte BLOBs in the
catalog and bodies are deduplicated in compressed ROOT shards. Certificates
are stored as canonical DER, interned once, and referenced by compact integer
IDs from crawl results.

A normal crawler exit closes its ROOT file but leaves the shard appendable.
Later runs reuse that shard; rollover seals it only once the file reaches about
1 GiB or is one week old. This keeps incremental snapshot backups coarse-grained
instead of creating a new body file for every crawler invocation.

All absolute times use signed Unix milliseconds and fields end in
`_unix_millis`. Gemini `meta` remains inline and unindexed; MIME is derived from
it rather than stored separately.

## Robots and TLS

The virtual identities are:

| Use | Applicable robots agents |
|---|---|
| `tlgs` | `*`, `indexer`, `tlgs` |
| `indexer` | `*`, `indexer`, `tardis` |
| `archiver` | `*`, `archiver`, `tardis` |
| `researcher` | `*`, `researcher`, `tardis` |
| `webproxy` | `*`, `webproxy`, `tardis` |

TLS validation intentionally checks only that the presented leaf certificate
names the requested host. In addition to normal wildcard matching, a certificate
for a parent host is accepted as an implicit one-label wildcard for Gemini client
compatibility (for example, `example.org` names `alice.example.org`). It does not
use a CA store, TOFU continuity, or certificate expiration as trust policy.

## Runtime controls

The defaults are two concurrent requests, four I/O loops, two hashing/parser
threads, five seconds between requests to one authority, 90 seconds for a
connection/header, and 120 seconds for a body transfer. `--max-pages` bounds a
validation run. Crawl progress is written to stdout; it updates in place on a
TTY and emits one line per `--progress-interval` seconds when redirected (one
second by default). `--status-port PORT` additionally exposes JSON at `/status`
on loopback.

TARDIS retains the curated exclusions in `src/exclusion.cpp`. They are applied
to seeds, watched pages, redirects, and discovered links before those URLs can
enter the queue. Independently, every literal or DNS-resolved peer address is
checked immediately before connection. Loopback, private, link-local,
carrier-grade NAT, multicast, documentation, transition, and other
special-purpose IPv4/IPv6 ranges are rejected, so a public hostname resolving
to an internal service cannot bypass the URL exclusions.

## SQLite query performance report

Run a crawler with `TARDIS_SQLITE_PROFILE=1` to emit the slowest SQLite
statements every five seconds and a cumulative report on exit. Each row reports
the total time spent inside `sqlite3_step`, number of steps, returned rows,
mean and maximum step time, followed by the SQL text.

```sh
TARDIS_SQLITE_PROFILE=1 ./build/tardis-crawler --snapshot data --persistent
```

The profiler is linked only into `tardis-crawler`; when disabled its cost is a
cached environment check before calling SQLite normally.
