//! Benchmarks: tosumu B+ tree vs SQLite (plain) and SQLite SEE AES-256 (encrypted).
//!
//! # Running
//!
//! Plain SQLite baseline (default):
//!   cargo bench -p tosumu-bench
//!
//! SQLite SEE comparison (AES-256):
//!   $env:SQLITE_SEE_DIR = 'F:\LocalSource\ClassLibrary\sqlite-see-efcore\see-sources'
//!   cargo bench -p tosumu-bench --no-default-features --features sqlite-see
//!
//! HTML reports are written to target/criterion/.
//!
//! # Groups
//!
//!   insert/plain      — 1 000-row single-txn insert into a fresh DB
//!   lookup/plain      — random point lookup from a 10 000-row DB
//!   scan_range/plain  — 100-key ordered range scan from a 10 000-row DB
//!   full_scan/plain   — scan all 10 000 rows
//!
//! When compiled with the `sqlite-see` feature the four groups above are also
//! benchmarked with encryption enabled:
//!   insert/encrypted  lookup/encrypted  scan_range/encrypted  full_scan/encrypted
//!
//! # What is measured
//!
//! Key: u64 big-endian (8 bytes) so byte-order lexicographic == numeric order.
//! Value: 128 bytes of fixed payload.
//! SQLite schema: `CREATE TABLE kv(key BLOB PRIMARY KEY, value BLOB) WITHOUT ROWID`
//! (a clustered B-tree — comparable structure to tosumu's B+ tree).
//! Both sides use WAL journal mode.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::path::Path;
use tempfile::TempDir;
use tosumu_core::page_store::PageStore;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of rows pre-loaded for lookup / scan benchmarks.
const ROWS: u64 = 10_000;

/// Rows inserted per transaction in the insert benchmarks.
const INSERT_BATCH: u64 = 1_000;

/// Keys returned per range-scan benchmark iteration.
const RANGE_SIZE: u64 = 100;

/// Fixed 128-byte value used for all benchmark rows.
const PAYLOAD: [u8; 128] = [0x42u8; 128];

/// Passphrase used for both tosumu and SQLite SEE encrypted bench DBs.
#[allow(dead_code)] // only referenced when sqlite_see cfg is active
const BENCH_PASS: &str = "tosumu-bench-passphrase";

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Encode a u64 as a big-endian byte key (byte order == numeric order).
#[inline]
fn u64_key(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

/// Xorshift64 PRNG — no external dependency, deterministic, non-zero seed.
#[inline]
fn xorshift64(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

/// Populate a PageStore with `count` sequential rows in one transaction.
fn populate_store(store: &mut PageStore, count: u64) {
    store
        .transaction(|s| {
            for i in 0..count {
                s.put(&u64_key(i), &PAYLOAD)?;
            }
            Ok(())
        })
        .expect("populate_store failed");
}

/// Open a plain (unencrypted) SQLite DB and create the kv table.
fn open_sqlite_plain(path: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).expect("sqlite open failed");
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; \
         CREATE TABLE IF NOT EXISTS kv(\
           key BLOB PRIMARY KEY, value BLOB\
         ) WITHOUT ROWID;",
    )
    .expect("sqlite setup failed");
    conn
}

/// Open a SEE-encrypted SQLite DB and create the kv table.
///
/// `PRAGMA key` must be the first pragma before any DB access.
#[cfg(sqlite_see)]
fn open_sqlite_see(path: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).expect("sqlite SEE open failed");
    conn.pragma_update(None, "key", BENCH_PASS)
        .expect("sqlite SEE PRAGMA key failed");
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; \
         CREATE TABLE IF NOT EXISTS kv(\
           key BLOB PRIMARY KEY, value BLOB\
         ) WITHOUT ROWID;",
    )
    .expect("sqlite SEE setup failed");
    conn
}

/// Populate a SQLite connection with `count` sequential rows in one transaction.
fn populate_sqlite(conn: &rusqlite::Connection, count: u64) {
    conn.execute_batch("BEGIN;").unwrap();
    let mut stmt = conn
        .prepare("INSERT OR REPLACE INTO kv(key,value) VALUES(?1,?2)")
        .unwrap();
    for i in 0..count {
        stmt.execute(rusqlite::params![u64_key(i).as_slice(), PAYLOAD.as_slice()])
            .unwrap();
    }
    drop(stmt);
    conn.execute_batch("COMMIT;").unwrap();
}

// ── insert/plain ──────────────────────────────────────────────────────────────

fn bench_insert_plain(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert/plain");
    group.throughput(Throughput::Elements(INSERT_BATCH));
    // DB creation is expensive; cap samples so the bench finishes quickly.
    group.sample_size(20);

    group.bench_function("tosumu", |b| {
        b.iter_batched(
            || TempDir::new().unwrap(),
            |dir| {
                let path = dir.path().join("bench.tsm");
                let mut store = PageStore::create(&path).unwrap();
                store
                    .transaction(|s| {
                        for i in 0..INSERT_BATCH {
                            s.put(&u64_key(i), &PAYLOAD)?;
                        }
                        Ok(())
                    })
                    .unwrap();
                (store, dir) // keep both alive until criterion drops the output
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("sqlite", |b| {
        b.iter_batched(
            || TempDir::new().unwrap(),
            |dir| {
                let path = dir.path().join("bench.db");
                let conn = open_sqlite_plain(&path);
                conn.execute_batch("BEGIN;").unwrap();
                let mut stmt = conn
                    .prepare("INSERT OR REPLACE INTO kv(key,value) VALUES(?1,?2)")
                    .unwrap();
                for i in 0..INSERT_BATCH {
                    stmt.execute(rusqlite::params![u64_key(i).as_slice(), PAYLOAD.as_slice()])
                        .unwrap();
                }
                drop(stmt);
                conn.execute_batch("COMMIT;").unwrap();
                (conn, dir)
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── lookup/plain ──────────────────────────────────────────────────────────────

fn bench_lookup_plain(c: &mut Criterion) {
    let mut group = c.benchmark_group("lookup/plain");
    group.throughput(Throughput::Elements(1));

    let tsm_dir = TempDir::new().unwrap();
    let mut store = PageStore::create(tsm_dir.path().join("bench.tsm").as_path()).unwrap();
    populate_store(&mut store, ROWS);

    let sql_dir = TempDir::new().unwrap();
    let conn = open_sqlite_plain(sql_dir.path().join("bench.db").as_path());
    populate_sqlite(&conn, ROWS);

    group.bench_function("tosumu", |b| {
        let mut rng = 0xdead_beef_cafe_u64;
        b.iter(|| {
            rng = xorshift64(rng);
            store.get(&u64_key(rng % ROWS)).unwrap()
        });
    });

    group.bench_function("sqlite", |b| {
        let mut rng = 0xdead_beef_cafe_u64;
        b.iter(|| {
            rng = xorshift64(rng);
            conn.query_row(
                "SELECT value FROM kv WHERE key=?1",
                rusqlite::params![u64_key(rng % ROWS).as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap()
        });
    });

    group.finish();
}

// ── scan_range/plain ──────────────────────────────────────────────────────────

fn bench_scan_range_plain(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_range/plain");
    group.throughput(Throughput::Elements(RANGE_SIZE));

    let tsm_dir = TempDir::new().unwrap();
    let mut store = PageStore::create(tsm_dir.path().join("bench.tsm").as_path()).unwrap();
    populate_store(&mut store, ROWS);

    let sql_dir = TempDir::new().unwrap();
    let conn = open_sqlite_plain(sql_dir.path().join("bench.db").as_path());
    populate_sqlite(&conn, ROWS);

    // Scan keys [1000, 1099] — well inside the populated range.
    let start = u64_key(1000);
    let end = u64_key(1000 + RANGE_SIZE - 1);

    group.bench_function("tosumu", |b| {
        b.iter(|| store.scan_range(&start, &end).unwrap());
    });

    group.bench_function("sqlite", |b| {
        b.iter(|| {
            let mut stmt = conn
                .prepare_cached("SELECT key,value FROM kv WHERE key>=?1 AND key<=?2")
                .unwrap();
            let rows: Vec<(Vec<u8>, Vec<u8>)> = stmt
                .query_map(rusqlite::params![start.as_slice(), end.as_slice()], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            rows
        });
    });

    group.finish();
}

// ── full_scan/plain ───────────────────────────────────────────────────────────

fn bench_full_scan_plain(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_scan/plain");
    group.throughput(Throughput::Elements(ROWS));

    let tsm_dir = TempDir::new().unwrap();
    let mut store = PageStore::create(tsm_dir.path().join("bench.tsm").as_path()).unwrap();
    populate_store(&mut store, ROWS);

    let sql_dir = TempDir::new().unwrap();
    let conn = open_sqlite_plain(sql_dir.path().join("bench.db").as_path());
    populate_sqlite(&conn, ROWS);

    group.bench_function("tosumu", |b| {
        b.iter(|| store.scan().unwrap());
    });

    group.bench_function("sqlite", |b| {
        b.iter(|| {
            let mut stmt = conn.prepare_cached("SELECT key,value FROM kv").unwrap();
            let rows: Vec<(Vec<u8>, Vec<u8>)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            rows
        });
    });

    group.finish();
}

// ── insert/encrypted ─────────────────────────────────────────────────────────

#[cfg(sqlite_see)]
fn bench_insert_encrypted(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert/encrypted");
    group.throughput(Throughput::Elements(INSERT_BATCH));
    group.sample_size(20);

    group.bench_function("tosumu-chacha20poly1305", |b| {
        b.iter_batched(
            || TempDir::new().unwrap(),
            |dir| {
                let path = dir.path().join("bench.tsm");
                let mut store = PageStore::create_encrypted(&path, BENCH_PASS).unwrap();
                store
                    .transaction(|s| {
                        for i in 0..INSERT_BATCH {
                            s.put(&u64_key(i), &PAYLOAD)?;
                        }
                        Ok(())
                    })
                    .unwrap();
                (store, dir)
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("sqlite-see-aes256", |b| {
        b.iter_batched(
            || TempDir::new().unwrap(),
            |dir| {
                let path = dir.path().join("bench.db");
                let conn = open_sqlite_see(&path);
                conn.execute_batch("BEGIN;").unwrap();
                let mut stmt = conn
                    .prepare("INSERT OR REPLACE INTO kv(key,value) VALUES(?1,?2)")
                    .unwrap();
                for i in 0..INSERT_BATCH {
                    stmt.execute(rusqlite::params![u64_key(i).as_slice(), PAYLOAD.as_slice()])
                        .unwrap();
                }
                drop(stmt);
                conn.execute_batch("COMMIT;").unwrap();
                (conn, dir)
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── lookup/encrypted ─────────────────────────────────────────────────────────

#[cfg(sqlite_see)]
fn bench_lookup_encrypted(c: &mut Criterion) {
    let mut group = c.benchmark_group("lookup/encrypted");
    group.throughput(Throughput::Elements(1));

    let tsm_dir = TempDir::new().unwrap();
    let mut store =
        PageStore::create_encrypted(tsm_dir.path().join("bench.tsm").as_path(), BENCH_PASS)
            .unwrap();
    populate_store(&mut store, ROWS);

    let sql_dir = TempDir::new().unwrap();
    let conn = open_sqlite_see(sql_dir.path().join("bench.db").as_path());
    populate_sqlite(&conn, ROWS);

    group.bench_function("tosumu-chacha20poly1305", |b| {
        let mut rng = 0xdead_beef_cafe_u64;
        b.iter(|| {
            rng = xorshift64(rng);
            store.get(&u64_key(rng % ROWS)).unwrap()
        });
    });

    group.bench_function("sqlite-see-aes256", |b| {
        let mut rng = 0xdead_beef_cafe_u64;
        b.iter(|| {
            rng = xorshift64(rng);
            conn.query_row(
                "SELECT value FROM kv WHERE key=?1",
                rusqlite::params![u64_key(rng % ROWS).as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap()
        });
    });

    group.finish();
}

// ── scan_range/encrypted ──────────────────────────────────────────────────────

#[cfg(sqlite_see)]
fn bench_scan_range_encrypted(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_range/encrypted");
    group.throughput(Throughput::Elements(RANGE_SIZE));

    let tsm_dir = TempDir::new().unwrap();
    let mut store =
        PageStore::create_encrypted(tsm_dir.path().join("bench.tsm").as_path(), BENCH_PASS)
            .unwrap();
    populate_store(&mut store, ROWS);

    let sql_dir = TempDir::new().unwrap();
    let conn = open_sqlite_see(sql_dir.path().join("bench.db").as_path());
    populate_sqlite(&conn, ROWS);

    let start = u64_key(1000);
    let end = u64_key(1000 + RANGE_SIZE - 1);

    group.bench_function("tosumu-chacha20poly1305", |b| {
        b.iter(|| store.scan_range(&start, &end).unwrap());
    });

    group.bench_function("sqlite-see-aes256", |b| {
        b.iter(|| {
            let mut stmt = conn
                .prepare_cached("SELECT key,value FROM kv WHERE key>=?1 AND key<=?2")
                .unwrap();
            let rows: Vec<(Vec<u8>, Vec<u8>)> = stmt
                .query_map(rusqlite::params![start.as_slice(), end.as_slice()], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            rows
        });
    });

    group.finish();
}

// ── full_scan/encrypted ───────────────────────────────────────────────────────

#[cfg(sqlite_see)]
fn bench_full_scan_encrypted(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_scan/encrypted");
    group.throughput(Throughput::Elements(ROWS));

    let tsm_dir = TempDir::new().unwrap();
    let mut store =
        PageStore::create_encrypted(tsm_dir.path().join("bench.tsm").as_path(), BENCH_PASS)
            .unwrap();
    populate_store(&mut store, ROWS);

    let sql_dir = TempDir::new().unwrap();
    let conn = open_sqlite_see(sql_dir.path().join("bench.db").as_path());
    populate_sqlite(&conn, ROWS);

    group.bench_function("tosumu-chacha20poly1305", |b| {
        b.iter(|| store.scan().unwrap());
    });

    group.bench_function("sqlite-see-aes256", |b| {
        b.iter(|| {
            let mut stmt = conn.prepare_cached("SELECT key,value FROM kv").unwrap();
            let rows: Vec<(Vec<u8>, Vec<u8>)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            rows
        });
    });

    group.finish();
}

// ── criterion groups ──────────────────────────────────────────────────────────

#[cfg(not(sqlite_see))]
criterion_group!(
    benches,
    bench_insert_plain,
    bench_lookup_plain,
    bench_scan_range_plain,
    bench_full_scan_plain,
);

#[cfg(sqlite_see)]
criterion_group!(
    benches,
    bench_insert_plain,
    bench_lookup_plain,
    bench_scan_range_plain,
    bench_full_scan_plain,
    bench_insert_encrypted,
    bench_lookup_encrypted,
    bench_scan_range_encrypted,
    bench_full_scan_encrypted,
);

criterion_main!(benches);
