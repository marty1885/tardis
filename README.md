# TARDIS

General purpsoe Geminispace crawler and archiver. Forked from the [TLGS](https://github.com/marty1885/tlgs) Geminispace search engine

To build and run TARDIS:

```sh
cmake -S . -B build
cmake --build build --parallel
./build/tardis-crawler --snapshot /path/to/your/data gemini://example.org/
```

Supplying a URL as a positional argument submits it to `crawl_queue`. Existing queued work can be resumed without supplying another seed:

```sh
./build/tardis-crawler --snapshot /path/to/your/data
```

Use `--persistent` to keep the process alive after the queue is clean. It will wait for scheduled watched pages and stop on a signal. Combine it with `--watch` for unattended recurring crawling, that adds a page to a 7 day update interval (plus or minus seom jitter):

```sh
./build/tardis-crawler --snapshot data --persistent \
  --watch gemini://example.org/
```

Use `--unwatch gemini://example.org/` to remove it from the recurring set.

## Robots and TLS

TARDIS is a general purpose crawler. It uses and maintains virtual identities so one crawl can be used to supply multiple applications.

| Use | Applicable robots agents |
|---|---|
| `tlgs` | `*`, `indexer`, `tlgs` |
| `indexer` | `*`, `indexer`, `tardis` |
| `archiver` | `*`, `archiver`, `tardis` |
| `researcher` | `*`, `researcher`, `tardis` |
| `webproxy` | `*`, `webproxy`, `tardis` |

TLS validation only checks that the presented leaf certificate names the requested host (because Lagrange allows, we can't meaningfully learn all reasons leading to certificate changes and Gemini is just.. chaotic). It accepts a matching subject CN even when the certificate also has a nonmatching SAN, and accepts wildcard CNs by suffix (including `*.com`), as Lagrange do. In addition to normal wildcard matching, a certificate for an ancestor host is accepted as an implicit wildcard for Gemini client compatibility (for example, `cities.yesterweb.org` names `bk.7z.cities.yesterweb.org`).

The crawler does however, check if the certificate is normal-net CA signed. To inform the "Changed Certificate" page about what is regular cerfificate rotation and what's violating TOFU.

## SQLite query performance debugging

Run a crawler with `TARDIS_SQLITE_PROFILE=1` to emit the slowest SQLite statements every five seconds and a cumulative report on exit. Each row reports the total time spent inside `sqlite3_step`, number of steps, returned rows, mean and maximum step time, followed by the SQL text.

```sh
TARDIS_SQLITE_PROFILE=1 ./build/tardis-crawler --snapshot data --persistent
```
