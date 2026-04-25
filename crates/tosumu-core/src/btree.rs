// B+ tree index on top of the Pager.
//
// Source of truth: DESIGN.md §5.5, §6.2.
//
// Layout recap
// ─────────────
// Page header (22 bytes):
//   [0]  page_type: u8
//   [1]  flags: u8
//   [2]  slot_count: u16 LE
//   [4]  free_start: u16 LE   (end of slot array)
//   [6]  free_end:   u16 LE   (start of heap, grows down)
//   [8]  fragmented_bytes: u16 LE
//   [10] reserved: u16
//   [12] reserved: u16
//   [14] next_leaf / leftmost_child: u64 LE
//        • leaf pages:     pgno of next leaf in sorted chain (0 = end)
//        • internal pages: pgno of leftmost child
//
// Leaf slot payload:   existing RECORD_LIVE / RECORD_TOMBSTONE wire format
// Internal slot payload: [right_child: u64 LE][key_len: u16 LE][key bytes]
//   Slot i represents the separator key whose right child is right_child.
//   leftmost_child lives in the page header (HDR_LEFTMOST).
//   Slots need not be in sorted order; find_child does a linear scan.
//
// Splits
// ──────
// Leaf split: read all records (LWW), split at midpoint, rewrite both halves,
//             link the new leaf into the chain, promote min-key-of-right upward.
// Internal split: collect all (sep_key, right_child) + leftmost, insert new entry,
//                 split at mid; promote entries[mid].key. Left keeps original
//                 leftmost; right's leftmost = entries[mid].right_child.
// Root split: allocate new root, leftmost = old_root, one slot = (promoted_key, new_half).

use std::path::Path;

use crate::error::{Result, TosumuError};
use crate::format::*;
use crate::pager::Pager;

// Page header field offsets — canonical definitions are PAGE_OFF_* in format.rs.
// Local aliases kept for readability within btree.rs.
const HDR_PAGE_TYPE: usize = PAGE_OFF_TYPE;
const HDR_SLOT_COUNT: usize = PAGE_OFF_SLOT_COUNT;
const HDR_FREE_START: usize = PAGE_OFF_FREE_START;
const HDR_FREE_END: usize = PAGE_OFF_FREE_END;
/// Dual-purpose field at offset 14:
/// • leaf pages:     pgno of next leaf in sorted order (0 = tail)
/// • internal pages: pgno of leftmost child
const HDR_LEFTMOST: usize = 14;

// Internal slot overhead: right_child(u64) + key_len(u16) = 10 bytes.
const INTERNAL_RECORD_OVERHEAD: usize = 10;

// Record-type discriminants (re-exported from format.rs via glob, kept explicit for clarity).
// RECORD_LIVE   = 0x01
// RECORD_TOMBSTONE = 0x02

/// B+ tree stored in a tosumu pager file.
pub struct BTree {
    pub(crate) pager: Pager,
}

impl BTree {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Create a new `.tsm` file with an empty B+ tree.
    pub fn create(path: &Path) -> Result<Self> {
        let mut pager = Pager::create(path)?;
        let root_pgno = pager.allocate(PAGE_TYPE_LEAF)?;
        pager.set_root_page(root_pgno)?;
        Ok(BTree { pager })
    }

    /// Create a new passphrase-encrypted `.tsm` file with an empty B+ tree.
    pub fn create_encrypted(path: &Path, passphrase: &str) -> Result<Self> {
        let mut pager = Pager::create_encrypted(path, passphrase)?;
        let root_pgno = pager.allocate(PAGE_TYPE_LEAF)?;
        pager.set_root_page(root_pgno)?;
        Ok(BTree { pager })
    }

    /// Open an existing `.tsm` file.
    pub fn open(path: &Path) -> Result<Self> {
        let pager = Pager::open(path)?;
        if pager.root_page() == 0 {
            return Err(TosumuError::Corrupt { pgno: 0, reason: "root_page is 0 — not a BTree file" });
        }
        Ok(BTree { pager })
    }

    /// Open an existing passphrase-protected `.tsm` file.
    pub fn open_with_passphrase(path: &Path, passphrase: &str) -> Result<Self> {
        let pager = Pager::open_with_passphrase(path, passphrase)?;
        if pager.root_page() == 0 {
            return Err(TosumuError::Corrupt { pgno: 0, reason: "root_page is 0 — not a BTree file" });
        }
        Ok(BTree { pager })
    }

    /// Open an existing recovery-key-protected `.tsm` file.
    pub fn open_with_recovery_key(path: &Path, recovery_str: &str) -> Result<Self> {
        let pager = Pager::open_with_recovery_key(path, recovery_str)?;
        if pager.root_page() == 0 {
            return Err(TosumuError::Corrupt { pgno: 0, reason: "root_page is 0 — not a BTree file" });
        }
        Ok(BTree { pager })
    }

    // ── Key management (delegates to Pager) ──────────────────────────────────

    pub fn add_passphrase_protector(path: &Path, unlock_passphrase: &str, new_passphrase: &str) -> Result<u16> {
        Pager::add_passphrase_protector(path, unlock_passphrase, new_passphrase)
    }

    pub fn add_recovery_key_protector(path: &Path, unlock_passphrase: &str) -> Result<String> {
        Pager::add_recovery_key_protector(path, unlock_passphrase)
    }

    pub fn remove_keyslot(path: &Path, unlock_passphrase: &str, slot_idx: u16) -> Result<()> {
        Pager::remove_keyslot(path, unlock_passphrase, slot_idx)
    }

    pub fn rekey_kek(path: &Path, slot_idx: u16, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        Pager::rekey_kek(path, slot_idx, old_passphrase, new_passphrase)
    }

    pub fn list_keyslots(path: &Path) -> Result<Vec<(u16, u8)>> {
        Pager::list_keyslots(path)
    }

    // ── Point operations ─────────────────────────────────────────────────────

    /// Look up `key`. Returns `Some(value)` if found and live, `None` otherwise.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let leaf_pgno = self.find_leaf(key)?;
        self.pager.with_page(leaf_pgno, |page| Ok(leaf_get(page, key)))
    }

    /// Insert or update `key` → `value`.
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let record = encode_live(key, value);
        let root = self.pager.root_page();
        if let Some((promoted_key, new_pgno)) = self.insert_record(root, key, &record)? {
            // Root split — allocate a new root internal page.
            let old_root = root;
            let new_root = self.pager.allocate(PAGE_TYPE_INTERNAL)?;
            self.pager.with_page_mut(new_root, |page| {
                write_u64(page, HDR_LEFTMOST, old_root);
                internal_slot_append(page, &promoted_key, new_pgno)
            })?;
            self.pager.set_root_page(new_root)?;
        }
        Ok(())
    }

    /// Delete `key`. No-op if the key does not exist.
    ///
    /// If the leaf has room, appends a tombstone (lazy delete). If the leaf is
    /// full, compacts it in place (removes the key from the live set).
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        let leaf_pgno = self.find_leaf(key)?;

        // Check the key is actually present.
        let exists = self.pager.with_page(leaf_pgno, |page| {
            Ok(leaf_get(page, key).is_some())
        })?;
        if !exists {
            return Ok(());
        }

        let tomb = encode_tombstone(key);
        let needed = SLOT_SIZE + tomb.len();
        let fits = self.pager.with_page(leaf_pgno, |page| {
            Ok(leaf_free_space(page) >= needed)
        })?;

        if fits {
            self.pager.with_page_mut(leaf_pgno, |page| leaf_slot_append(page, &tomb))
        } else {
            // Compact: rewrite leaf without the deleted key.
            let (mut live, next) = self.pager.with_page(leaf_pgno, |page| {
                let live = leaf_read_all_live(page);
                let next = read_u64(page, HDR_LEFTMOST);
                Ok((live, next))
            })?;
            live.retain(|(k, _)| k.as_slice() != key);
            self.pager.with_page_mut(leaf_pgno, |page| {
                leaf_rewrite(page, next, &live)
            })
        }
    }

    // ── Range scan ───────────────────────────────────────────────────────────

    /// Return all live key-value pairs where `start <= key <= end`, sorted by key.
    ///
    /// Descends to the leaf containing `start`, then walks the leaf chain forward.
    /// Stops as soon as any key on the current page exceeds `end`: the B+ tree
    /// invariant guarantees that all keys on subsequent pages in the chain are
    /// >= the page-separator between the current and next page, which is > any
    /// key on the current page, so those pages cannot contain in-range keys.
    pub fn scan_by_key(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let first_leaf = self.find_leaf(start)?;
        let mut map: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>> = Default::default();
        let mut cursor = first_leaf;

        loop {
            // Returns (next_pgno, past_end).
            // past_end = true when any key on this page exceeded `end`, meaning
            // the next page in the chain is entirely beyond the range.
            let (next, past_end) = self.pager.with_page(cursor, |page| {
                let next_pgno = read_u64(page, HDR_LEFTMOST);
                let slot_count = read_u16(page, HDR_SLOT_COUNT) as usize;
                let mut past_end = false;
                for i in 0..slot_count {
                    let slot_pos = PAGE_HEADER_SIZE + i * SLOT_SIZE;
                    let off = read_u16(page, slot_pos) as usize;
                    let len = read_u16(page, slot_pos + 2) as usize;
                    if off + len > PAGE_PLAINTEXT_SIZE { continue; }
                    let rec = &page[off..off + len];
                    if rec.is_empty() { continue; }
                    match rec[0] {
                        RECORD_LIVE if rec.len() >= 5 => {
                            let kl = u16::from_le_bytes([rec[1], rec[2]]) as usize;
                            let vl = u16::from_le_bytes([rec[3], rec[4]]) as usize;
                            if 5 + kl + vl == rec.len() {
                                let k = &rec[5..5 + kl];
                                if k > end {
                                    past_end = true;
                                } else if k >= start {
                                    map.insert(k.to_vec(), Some(rec[5 + kl..5 + kl + vl].to_vec()));
                                }
                            }
                        }
                        RECORD_TOMBSTONE if rec.len() >= 3 => {
                            let kl = u16::from_le_bytes([rec[1], rec[2]]) as usize;
                            if 3 + kl == rec.len() {
                                let k = &rec[3..3 + kl];
                                if k > end {
                                    past_end = true;
                                } else if k >= start {
                                    map.insert(k.to_vec(), None);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok((next_pgno, past_end))
            })?;
            if next == 0 || past_end { break; }
            cursor = next;
        }

        Ok(map.into_iter().filter_map(|(k, v)| v.map(|val| (k, val))).collect())
    }

    /// Scan all pages in physical order (for debugging / verification).
    pub fn scan_physical(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut map: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>> = Default::default();
        for pgno in 1..self.pager.page_count() {
            self.pager.with_page(pgno, |page| {
                match page[HDR_PAGE_TYPE] {
                    PAGE_TYPE_LEAF => {}
                    PAGE_TYPE_INTERNAL => return Ok(()),
                    _ => return Err(TosumuError::Corrupt {
                        pgno,
                        reason: "unknown page type in physical scan",
                    }),
                }
                let slot_count = read_u16(page, HDR_SLOT_COUNT) as usize;
                for i in 0..slot_count {
                    let slot_pos = PAGE_HEADER_SIZE + i * SLOT_SIZE;
                    let off = read_u16(page, slot_pos) as usize;
                    let len = read_u16(page, slot_pos + 2) as usize;
                    if off + len > PAGE_PLAINTEXT_SIZE { continue; }
                    let rec = &page[off..off + len];
                    if rec.is_empty() { continue; }
                    match rec[0] {
                        RECORD_LIVE if rec.len() >= 5 => {
                            let kl = u16::from_le_bytes([rec[1], rec[2]]) as usize;
                            let vl = u16::from_le_bytes([rec[3], rec[4]]) as usize;
                            if 5 + kl + vl == rec.len() {
                                let k = rec[5..5 + kl].to_vec();
                                let v = rec[5 + kl..5 + kl + vl].to_vec();
                                map.insert(k, Some(v));
                            }
                        }
                        RECORD_TOMBSTONE if rec.len() >= 3 => {
                            let kl = u16::from_le_bytes([rec[1], rec[2]]) as usize;
                            if 3 + kl == rec.len() {
                                let k = rec[3..3 + kl].to_vec();
                                map.insert(k, None);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(())
            })?;
        }
        Ok(map.into_iter().filter_map(|(k, v)| v.map(|val| (k, val))).collect())
    }

    /// Return the current page count (header page + data pages).
    pub fn page_count(&self) -> u64 { self.pager.page_count() }

    /// Return the root page number.
    pub fn root_page(&self) -> u64 { self.pager.root_page() }

    /// Begin a write transaction on the underlying pager.
    pub(crate) fn begin_txn(&mut self) -> Result<()> { self.pager.begin_txn() }

    /// Commit the current transaction (fsync WAL + flush dirty pages to .tsm).
    pub(crate) fn commit_txn(&mut self) -> Result<()> { self.pager.commit_txn() }

    /// Roll back the current transaction (discard dirty pages).
    pub(crate) fn rollback_txn(&mut self) { self.pager.rollback_txn() }

    /// Walk from the root to the leftmost leaf and return the height (1 = single leaf).
    pub fn tree_height(&self) -> Result<usize> {
        let mut pgno = self.pager.root_page();
        let mut h = 1;
        loop {
            let page_type = self.pager.with_page(pgno, |page| Ok(page[HDR_PAGE_TYPE]))?;
            if page_type == PAGE_TYPE_LEAF { return Ok(h); }
            pgno = self.pager.with_page(pgno, |page| Ok(read_u64(page, HDR_LEFTMOST)))?;
            h += 1;
        }
    }

    // ── Private — traversal ──────────────────────────────────────────────────

    /// Traverse internal pages to reach the leaf that contains (or should contain) `key`.
    fn find_leaf(&self, key: &[u8]) -> Result<u64> {
        let mut pgno = self.pager.root_page();
        loop {
            let page_type = self.pager.with_page(pgno, |page| Ok(page[HDR_PAGE_TYPE]))?;
            match page_type {
                PAGE_TYPE_LEAF => return Ok(pgno),
                PAGE_TYPE_INTERNAL => {
                    pgno = self.pager.with_page(pgno, |page| internal_find_child(page, pgno, key))?;
                }
                _ => return Err(TosumuError::Corrupt { pgno, reason: "unexpected page type during traversal" }),
            }
        }
    }

    // ── Private — recursive insert ───────────────────────────────────────────

    /// Recursively insert `record` (keyed by `sort_key`) into the subtree rooted at `pgno`.
    ///
    /// Returns `Some((promoted_key, new_pgno))` when the node split; `None` otherwise.
    fn insert_record(
        &mut self,
        pgno: u64,
        sort_key: &[u8],
        record: &[u8],
    ) -> Result<Option<(Vec<u8>, u64)>> {
        let page_type = self.pager.with_page(pgno, |page| Ok(page[HDR_PAGE_TYPE]))?;

        if page_type == PAGE_TYPE_LEAF {
            let needed = SLOT_SIZE + record.len();
            let fits = self.pager.with_page(pgno, |page| Ok(leaf_free_space(page) >= needed))?;
            if fits {
                self.pager.with_page_mut(pgno, |page| leaf_slot_append(page, record))?;
                return Ok(None);
            }
            return self.split_leaf(pgno, sort_key, record);
        }

        // Internal page: recurse into the child that covers sort_key.
        let child_pgno = self.pager.with_page(pgno, |page| internal_find_child(page, pgno, sort_key))?;
        let split = self.insert_record(child_pgno, sort_key, record)?;

        let Some((promoted_key, new_child)) = split else {
            return Ok(None);
        };

        // Absorb the split into this internal page.
        let needed = SLOT_SIZE + INTERNAL_RECORD_OVERHEAD + promoted_key.len();
        let fits = self.pager.with_page(pgno, |page| Ok(leaf_free_space(page) >= needed))?;
        if fits {
            self.pager.with_page_mut(pgno, |page| internal_slot_append(page, &promoted_key, new_child))?;
            return Ok(None);
        }
        self.split_internal(pgno, &promoted_key, new_child)
    }

    // ── Private — splits ─────────────────────────────────────────────────────

    /// Split a full leaf page. Inserts `new_record` (keyed by `sort_key`) among the existing
    /// records, redistributes into left/right halves, links the new leaf, and returns the
    /// split key to promote.
    fn split_leaf(&mut self, pgno: u64, sort_key: &[u8], new_record: &[u8]) -> Result<Option<(Vec<u8>, u64)>> {
        // Collect all live records from the old leaf (LWW-deduplicated).
        let (mut records, old_next) = self.pager.with_page(pgno, |page| {
            Ok((leaf_read_all_live(page), read_u64(page, HDR_LEFTMOST)))
        })?;

        // Insert new record in key-sorted position (replacing existing key if present).
        let sort_key_vec = sort_key.to_vec();
        records.retain(|(k, _)| k != &sort_key_vec);
        let pos = records.partition_point(|(k, _)| k.as_slice() < sort_key);

        // Decode the new record to extract value for the records list.
        match new_record[0] {
            RECORD_LIVE if new_record.len() >= 5 => {
                let kl = u16::from_le_bytes([new_record[1], new_record[2]]) as usize;
                let vl = u16::from_le_bytes([new_record[3], new_record[4]]) as usize;
                if 5 + kl + vl == new_record.len() {
                    let v = new_record[5 + kl..5 + kl + vl].to_vec();
                    records.insert(pos, (sort_key_vec, v));
                }
            }
            RECORD_TOMBSTONE => {
                // Tombstone on a full page: key was already removed by retain above.
                // Just rewrite without it.
            }
            _ => {}
        }

        let mid = records.len() / 2;
        let split_key = records[mid].0.clone();

        // Allocate new leaf, write right half into it.
        let new_pgno = self.pager.allocate(PAGE_TYPE_LEAF)?;
        let right: Vec<_> = records[mid..].to_vec();
        self.pager.with_page_mut(new_pgno, |page| {
            leaf_rewrite(page, old_next, &right)
        })?;

        // Rewrite left half into old page; link it to new leaf.
        let left: Vec<_> = records[..mid].to_vec();
        self.pager.with_page_mut(pgno, |page| {
            leaf_rewrite(page, new_pgno, &left)
        })?;

        Ok(Some((split_key, new_pgno)))
    }

    /// Split a full internal page after absorbing a child split.
    ///
    /// After the split, the promoted key rises further up (or creates a new root).
    fn split_internal(&mut self, pgno: u64, new_sep: &[u8], new_child: u64) -> Result<Option<(Vec<u8>, u64)>> {
        // Collect all (sep_key, right_child) + leftmost_child from old page.
        let (mut entries, leftmost) = self.pager.with_page(pgno, |page| {
            Ok(internal_read_all(page))
        })?;

        // Insert new separator in position (unsorted is fine; find_child scans all).
        entries.push((new_sep.to_vec(), new_child));
        // Sort to make mid-split deterministic.
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));

        let mid = entries.len() / 2;
        let promote_key = entries[mid].0.clone();
        let right_leftmost = entries[mid].1;

        // Right node: leftmost = entries[mid].right_child, slots = entries[mid+1..]
        let new_pgno = self.pager.allocate(PAGE_TYPE_INTERNAL)?;
        let right: Vec<_> = entries[mid + 1..].to_vec();
        self.pager.with_page_mut(new_pgno, |page| {
            *page = [0u8; PAGE_PLAINTEXT_SIZE];
            page[HDR_PAGE_TYPE] = PAGE_TYPE_INTERNAL;
            write_u16(page, HDR_SLOT_COUNT, 0);
            write_u16(page, HDR_FREE_START, PAGE_HEADER_SIZE as u16);
            write_u16(page, HDR_FREE_END, PAGE_PLAINTEXT_SIZE as u16);
            write_u64(page, HDR_LEFTMOST, right_leftmost);
            for (k, c) in &right {
                internal_slot_append(page, k, *c)?;
            }
            Ok(())
        })?;

        // Left node: leftmost = original leftmost, slots = entries[..mid]
        let left: Vec<_> = entries[..mid].to_vec();
        self.pager.with_page_mut(pgno, |page| {
            *page = [0u8; PAGE_PLAINTEXT_SIZE];
            page[HDR_PAGE_TYPE] = PAGE_TYPE_INTERNAL;
            write_u16(page, HDR_SLOT_COUNT, 0);
            write_u16(page, HDR_FREE_START, PAGE_HEADER_SIZE as u16);
            write_u16(page, HDR_FREE_END, PAGE_PLAINTEXT_SIZE as u16);
            write_u64(page, HDR_LEFTMOST, leftmost);
            for (k, c) in &left {
                internal_slot_append(page, k, *c)?;
            }
            Ok(())
        })?;

        Ok(Some((promote_key, new_pgno)))
    }

    // ── Invariant checker ────────────────────────────────────────────────────

    /// Verify structural invariants of the B+ tree.
    ///
    /// Checks performed (insert-only build; half-occupancy deferred until
    /// delete/merge rebalancing exists):
    /// - Root is non-zero and has a valid page type
    /// - Every visited page is PAGE_TYPE_LEAF or PAGE_TYPE_INTERNAL
    /// - Every slot has in-bounds offset and length
    /// - Separator keys within each internal node are distinct
    /// - Separator routing: each child subtree's min/max live key respects its enclosing separators
    /// - All leaves are at the same depth from the root
    /// - Live keys within each leaf are sorted (LWW-deduplicated)
    /// - Leaf chain is ordered: first live key of leaf N+1 > last live key of leaf N
    /// - No duplicate live keys across the entire tree
    pub fn check_invariants(&self) -> Result<()> {
        let root = self.pager.root_page();
        if root == 0 {
            return Err(TosumuError::Corrupt { pgno: 0, reason: "root_page is 0" });
        }
        let root_type = self.pager.with_page(root, |p| Ok(p[HDR_PAGE_TYPE]))?;
        if root_type != PAGE_TYPE_LEAF && root_type != PAGE_TYPE_INTERNAL {
            return Err(TosumuError::Corrupt { pgno: root, reason: "root has unexpected page type" });
        }
        self.inv_check_subtree(root)?;
        self.inv_check_leaf_chain(root)?;
        Ok(())
    }

    /// DFS invariant check on the subtree rooted at `pgno`.
    ///
    /// Returns `(min_live_key, max_live_key, depth)` where min/max are `None`
    /// when the subtree contains no live keys, and depth is 1 at a leaf.
    fn inv_check_subtree(
        &self,
        pgno: u64,
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, usize)> {
        let page_type = self.pager.with_page(pgno, |p| Ok(p[HDR_PAGE_TYPE]))?;
        match page_type {
            PAGE_TYPE_LEAF => {
                let live_keys = self.pager.with_page(pgno, |page| {
                    inv_check_slots(page, pgno)?;
                    let keys: Vec<Vec<u8>> = leaf_read_all_live(page)
                        .into_iter()
                        .map(|(k, _)| k)
                        .collect();
                    Ok(keys)
                })?;
                // leaf_read_all_live uses BTreeMap so keys emerge sorted.
                // Verify explicitly for the invariant record.
                for i in 1..live_keys.len() {
                    if live_keys[i] <= live_keys[i - 1] {
                        return Err(TosumuError::Corrupt {
                            pgno,
                            reason: "leaf live keys are not strictly sorted",
                        });
                    }
                }
                Ok((live_keys.first().cloned(), live_keys.last().cloned(), 1))
            }
            PAGE_TYPE_INTERNAL => {
                let (mut entries, leftmost) = self.pager.with_page(pgno, |page| {
                    inv_check_slots(page, pgno)?;
                    Ok(internal_read_all(page))
                })?;
                if leftmost == 0 {
                    return Err(TosumuError::Corrupt {
                        pgno,
                        reason: "internal page has zero leftmost child",
                    });
                }
                // Sort by separator so routing checks are deterministic regardless of slot order.
                entries.sort_by(|(a, _), (b, _)| a.cmp(b));
                // Separators must be distinct.
                for i in 1..entries.len() {
                    if entries[i].0 == entries[i - 1].0 {
                        return Err(TosumuError::Corrupt {
                            pgno,
                            reason: "internal page contains duplicate separator keys",
                        });
                    }
                }
                // All right-child pgnos must be non-zero.
                for (_, child) in &entries {
                    if *child == 0 {
                        return Err(TosumuError::Corrupt {
                            pgno,
                            reason: "internal slot has zero right child",
                        });
                    }
                }
                // Recurse into leftmost child.
                let (lc_min, lc_max, depth) = self.inv_check_subtree(leftmost)?;
                // leftmost child's max must be < first separator.
                if let (Some(ref max_k), Some(first_sep)) = (&lc_max, entries.first()) {
                    if max_k.as_slice() >= first_sep.0.as_slice() {
                        return Err(TosumuError::Corrupt {
                            pgno,
                            reason: "leftmost child max key >= first separator (routing error)",
                        });
                    }
                }
                let mut overall_min = lc_min;
                let mut overall_max = lc_max;
                // Recurse into right children.
                for i in 0..entries.len() {
                    let (sep_key, right_child) = &entries[i];
                    let (child_min, child_max, child_depth) = self.inv_check_subtree(*right_child)?;
                    if child_depth != depth {
                        return Err(TosumuError::Corrupt {
                            pgno,
                            reason: "children are at different depths (unbalanced tree)",
                        });
                    }
                    // child min must be >= sep_key.
                    if let Some(ref min_k) = child_min {
                        if min_k.as_slice() < sep_key.as_slice() {
                            return Err(TosumuError::Corrupt {
                                pgno,
                                reason: "right subtree min key < separator (routing error)",
                            });
                        }
                    }
                    // child max must be < next separator (if one exists).
                    if let Some(ref max_k) = child_max {
                        if let Some(next_sep) = entries.get(i + 1) {
                            if max_k.as_slice() >= next_sep.0.as_slice() {
                                return Err(TosumuError::Corrupt {
                                    pgno,
                                    reason: "right subtree max key >= next separator (routing error)",
                                });
                            }
                        }
                    }
                    if let Some(ref k) = child_min {
                        match overall_min {
                            None => overall_min = Some(k.clone()),
                            Some(ref cur) if k < cur => overall_min = Some(k.clone()),
                            _ => {}
                        }
                    }
                    if let Some(ref k) = child_max {
                        match overall_max {
                            None => overall_max = Some(k.clone()),
                            Some(ref cur) if k > cur => overall_max = Some(k.clone()),
                            _ => {}
                        }
                    }
                }
                Ok((overall_min, overall_max, 1 + depth))
            }
            _ => Err(TosumuError::Corrupt {
                pgno,
                reason: "unexpected page type in tree traversal",
            }),
        }
    }

    /// Walk the leaf chain, checking:
    /// - All pages in the chain are PAGE_TYPE_LEAF
    /// - first live key of each leaf > last live key of its predecessor
    /// - No live key appears in more than one leaf
    fn inv_check_leaf_chain(&self, root: u64) -> Result<()> {
        // Descend to the leftmost leaf.
        let mut pgno = root;
        loop {
            let page_type = self.pager.with_page(pgno, |p| Ok(p[HDR_PAGE_TYPE]))?;
            if page_type == PAGE_TYPE_LEAF { break; }
            pgno = self.pager.with_page(pgno, |p| Ok(read_u64(p, HDR_LEFTMOST)))?;
        }
        let mut seen: std::collections::HashSet<Vec<u8>> = Default::default();
        let mut prev_max: Option<Vec<u8>> = None;
        loop {
            let (live_keys, next) = self.pager.with_page(pgno, |page| {
                if page[HDR_PAGE_TYPE] != PAGE_TYPE_LEAF {
                    return Err(TosumuError::Corrupt {
                        pgno,
                        reason: "non-leaf page encountered in leaf chain",
                    });
                }
                let keys: Vec<Vec<u8>> = leaf_read_all_live(page)
                    .into_iter()
                    .map(|(k, _)| k)
                    .collect();
                Ok((keys, read_u64(page, HDR_LEFTMOST)))
            })?;
            if let (Some(ref prev), Some(first)) = (&prev_max, live_keys.first()) {
                if first <= prev {
                    return Err(TosumuError::Corrupt {
                        pgno,
                        reason: "leaf chain out of order: first key <= previous leaf max key",
                    });
                }
            }
            for k in &live_keys {
                if !seen.insert(k.clone()) {
                    return Err(TosumuError::Corrupt {
                        pgno,
                        reason: "duplicate live key found in leaf chain",
                    });
                }
            }
            prev_max = live_keys.last().cloned();
            if next == 0 { break; }
            pgno = next;
        }
        Ok(())
    }
}

// ── Internal page helpers ─────────────────────────────────────────────────────

/// Find the child pgno to follow for `key` in an internal page.
///
/// Returns the rightmost slot's child whose separator key <= key, or
/// leftmost_child if key is less than all separator keys.
fn internal_find_child(page: &[u8; PAGE_PLAINTEXT_SIZE], pgno: u64, key: &[u8]) -> Result<u64> {
    let leftmost = read_u64(page, HDR_LEFTMOST);
    let slot_count = read_u16(page, HDR_SLOT_COUNT) as usize;

    // Linear scan: find the rightmost separator key ≤ key.
    let mut result = leftmost;
    for i in 0..slot_count {
        let (sep_key, right_child) = read_internal_slot(page, pgno, i)?;
        if key >= sep_key.as_slice() {
            result = right_child;
        }
    }
    Ok(result)
}

/// Read the i-th internal slot: returns (separator_key, right_child_pgno).
fn read_internal_slot(page: &[u8; PAGE_PLAINTEXT_SIZE], pgno: u64, i: usize) -> Result<(Vec<u8>, u64)> {
    let slot_pos = PAGE_HEADER_SIZE + i * SLOT_SIZE;
    let off = read_u16(page, slot_pos) as usize;
    let len = read_u16(page, slot_pos + 2) as usize;
    if off + len > PAGE_PLAINTEXT_SIZE || len < INTERNAL_RECORD_OVERHEAD {
        return Err(TosumuError::Corrupt { pgno, reason: "invalid internal slot" });
    }
    let rec = &page[off..off + len];
    let right_child = u64::from_le_bytes(rec[0..8].try_into().unwrap());
    let key_len = u16::from_le_bytes([rec[8], rec[9]]) as usize;
    if 10 + key_len > len {
        return Err(TosumuError::Corrupt { pgno, reason: "internal slot key overflow" });
    }
    Ok((rec[10..10 + key_len].to_vec(), right_child))
}

/// Collect all (separator_key, right_child) entries plus leftmost_child from an internal page.
fn internal_read_all(page: &[u8; PAGE_PLAINTEXT_SIZE]) -> (Vec<(Vec<u8>, u64)>, u64) {
    let leftmost = read_u64(page, HDR_LEFTMOST);
    let slot_count = read_u16(page, HDR_SLOT_COUNT) as usize;
    let mut entries = Vec::with_capacity(slot_count);
    for i in 0..slot_count {
        if let Ok((k, c)) = read_internal_slot(page, 0, i) {
            entries.push((k, c));
        }
    }
    (entries, leftmost)
}

/// Append a separator slot `(sep_key, right_child)` to an internal page.
fn internal_slot_append(page: &mut [u8; PAGE_PLAINTEXT_SIZE], sep_key: &[u8], right_child: u64) -> Result<()> {
    let mut rec = Vec::with_capacity(INTERNAL_RECORD_OVERHEAD + sep_key.len());
    rec.extend_from_slice(&right_child.to_le_bytes());
    rec.extend_from_slice(&(sep_key.len() as u16).to_le_bytes());
    rec.extend_from_slice(sep_key);
    leaf_slot_append(page, &rec) // same slotted-page append logic
}

// ── Leaf page helpers ─────────────────────────────────────────────────────────

/// Return the most recent live value for `key` in a leaf page, or `None`.
fn leaf_get(page: &[u8; PAGE_PLAINTEXT_SIZE], key: &[u8]) -> Option<Vec<u8>> {
    let slot_count = read_u16(page, HDR_SLOT_COUNT) as usize;
    let mut result: Option<Option<Vec<u8>>> = None;

    for i in 0..slot_count {
        let slot_pos = PAGE_HEADER_SIZE + i * SLOT_SIZE;
        let off = read_u16(page, slot_pos) as usize;
        let len = read_u16(page, slot_pos + 2) as usize;
        if off + len > PAGE_PLAINTEXT_SIZE { continue; }
        let rec = &page[off..off + len];
        if rec.is_empty() { continue; }
        match rec[0] {
            RECORD_LIVE if rec.len() >= 5 => {
                let kl = u16::from_le_bytes([rec[1], rec[2]]) as usize;
                let vl = u16::from_le_bytes([rec[3], rec[4]]) as usize;
                if 5 + kl + vl == rec.len() && &rec[5..5 + kl] == key {
                    result = Some(Some(rec[5 + kl..5 + kl + vl].to_vec()));
                }
            }
            RECORD_TOMBSTONE if rec.len() >= 3 => {
                let kl = u16::from_le_bytes([rec[1], rec[2]]) as usize;
                if 3 + kl == rec.len() && &rec[3..3 + kl] == key {
                    result = Some(None);
                }
            }
            _ => {}
        }
    }
    result.flatten()
}

/// Read all live (key, value) pairs from a leaf, applying last-write-wins semantics.
fn leaf_read_all_live(page: &[u8; PAGE_PLAINTEXT_SIZE]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let slot_count = read_u16(page, HDR_SLOT_COUNT) as usize;
    let mut map: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>> = Default::default();

    for i in 0..slot_count {
        let slot_pos = PAGE_HEADER_SIZE + i * SLOT_SIZE;
        let off = read_u16(page, slot_pos) as usize;
        let len = read_u16(page, slot_pos + 2) as usize;
        if off + len > PAGE_PLAINTEXT_SIZE { continue; }
        let rec = &page[off..off + len];
        if rec.is_empty() { continue; }
        match rec[0] {
            RECORD_LIVE if rec.len() >= 5 => {
                let kl = u16::from_le_bytes([rec[1], rec[2]]) as usize;
                let vl = u16::from_le_bytes([rec[3], rec[4]]) as usize;
                if 5 + kl + vl == rec.len() {
                    let k = rec[5..5 + kl].to_vec();
                    let v = rec[5 + kl..5 + kl + vl].to_vec();
                    map.insert(k, Some(v));
                }
            }
            RECORD_TOMBSTONE if rec.len() >= 3 => {
                let kl = u16::from_le_bytes([rec[1], rec[2]]) as usize;
                if 3 + kl == rec.len() {
                    let k = rec[3..3 + kl].to_vec();
                    map.insert(k, None);
                }
            }
            _ => {}
        }
    }
    map.into_iter().filter_map(|(k, v)| v.map(|val| (k, val))).collect()
}

/// Append a raw record to a leaf page using the slotted-page format.
fn leaf_slot_append(page: &mut [u8; PAGE_PLAINTEXT_SIZE], record: &[u8]) -> Result<()> {
    let slot_count = read_u16(page, HDR_SLOT_COUNT) as usize;
    let free_start = read_u16(page, HDR_FREE_START) as usize;
    let free_end = read_u16(page, HDR_FREE_END) as usize;

    if free_end.saturating_sub(free_start) < SLOT_SIZE + record.len() {
        return Err(TosumuError::OutOfSpace);
    }

    let rec_offset = free_end - record.len();
    page[rec_offset..rec_offset + record.len()].copy_from_slice(record);

    let slot_pos = free_start;
    write_u16(page, slot_pos, rec_offset as u16);
    write_u16(page, slot_pos + 2, record.len() as u16);

    write_u16(page, HDR_SLOT_COUNT, (slot_count + 1) as u16);
    write_u16(page, HDR_FREE_START, (free_start + SLOT_SIZE) as u16);
    write_u16(page, HDR_FREE_END, rec_offset as u16);

    Ok(())
}

/// Clear a leaf page and rewrite it with the given live records.
///
/// `next` is the new value for HDR_LEFTMOST (leaf-chain pointer).
fn leaf_rewrite(page: &mut [u8; PAGE_PLAINTEXT_SIZE], next: u64, records: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
    *page = [0u8; PAGE_PLAINTEXT_SIZE];
    page[HDR_PAGE_TYPE] = PAGE_TYPE_LEAF;
    write_u16(page, HDR_SLOT_COUNT, 0);
    write_u16(page, HDR_FREE_START, PAGE_HEADER_SIZE as u16);
    write_u16(page, HDR_FREE_END, PAGE_PLAINTEXT_SIZE as u16);
    write_u64(page, HDR_LEFTMOST, next);
    for (k, v) in records {
        let rec = encode_live(k, v);
        leaf_slot_append(page, &rec)?;
    }
    Ok(())
}

/// Available free bytes between the slot array and the heap.
fn leaf_free_space(page: &[u8; PAGE_PLAINTEXT_SIZE]) -> usize {
    let free_start = read_u16(page, HDR_FREE_START) as usize;
    let free_end = read_u16(page, HDR_FREE_END) as usize;
    free_end.saturating_sub(free_start)
}

// ── Invariant helper ─────────────────────────────────────────────────────────

/// Validate that all slot offset+length pairs in `page` are in-bounds.
fn inv_check_slots(page: &[u8; PAGE_PLAINTEXT_SIZE], pgno: u64) -> Result<()> {
    let slot_count  = read_u16(page, HDR_SLOT_COUNT) as usize;
    let free_start  = read_u16(page, HDR_FREE_START) as usize;
    let free_end    = read_u16(page, HDR_FREE_END)   as usize;
    let slot_array_end = PAGE_HEADER_SIZE + slot_count * SLOT_SIZE;
    if slot_array_end > free_start {
        return Err(TosumuError::Corrupt { pgno, reason: "slot array end exceeds free_start" });
    }
    if free_start > free_end {
        return Err(TosumuError::Corrupt { pgno, reason: "free_start > free_end" });
    }
    if free_end > PAGE_PLAINTEXT_SIZE {
        return Err(TosumuError::Corrupt { pgno, reason: "free_end > PAGE_PLAINTEXT_SIZE" });
    }
    for i in 0..slot_count {
        let slot_pos = PAGE_HEADER_SIZE + i * SLOT_SIZE;
        let off = read_u16(page, slot_pos) as usize;
        let len = read_u16(page, slot_pos + 2) as usize;
        if len == 0 {
            return Err(TosumuError::Corrupt { pgno, reason: "slot has zero length" });
        }
        if off < free_end {
            return Err(TosumuError::Corrupt { pgno, reason: "slot offset below free_end (overlaps free area)" });
        }
        if off + len > PAGE_PLAINTEXT_SIZE {
            return Err(TosumuError::Corrupt { pgno, reason: "slot offset+length exceeds page boundary" });
        }
    }
    Ok(())
}

// ── Record encoding ───────────────────────────────────────────────────────────

fn encode_live(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(5 + key.len() + value.len());
    r.push(RECORD_LIVE);
    r.extend_from_slice(&(key.len() as u16).to_le_bytes());
    r.extend_from_slice(&(value.len() as u16).to_le_bytes());
    r.extend_from_slice(key);
    r.extend_from_slice(value);
    r
}

fn encode_tombstone(key: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(3 + key.len());
    r.push(RECORD_TOMBSTONE);
    r.extend_from_slice(&(key.len() as u16).to_le_bytes());
    r.extend_from_slice(key);
    r
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tosumu_btree_{name}_{}.tsm",
            std::process::id()
        ))
    }

    #[test]
    fn btree_put_get_round_trip() {
        let p = tmp("round_trip");
        let _ = std::fs::remove_file(&p);

        let mut t = BTree::create(&p).unwrap();
        t.put(b"alpha", b"1").unwrap();
        t.put(b"beta", b"2").unwrap();
        t.put(b"gamma", b"3").unwrap();

        assert_eq!(t.get(b"alpha").unwrap(), Some(b"1".to_vec()));
        assert_eq!(t.get(b"beta").unwrap(), Some(b"2".to_vec()));
        assert_eq!(t.get(b"gamma").unwrap(), Some(b"3".to_vec()));
        assert_eq!(t.get(b"missing").unwrap(), None);

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn btree_open_persists() {
        let p = tmp("persist");
        let _ = std::fs::remove_file(&p);

        {
            let mut t = BTree::create(&p).unwrap();
            t.put(b"x", b"hello").unwrap();
        }

        let t = BTree::open(&p).unwrap();
        assert_eq!(t.get(b"x").unwrap(), Some(b"hello".to_vec()));

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn btree_delete_removes_key() {
        let p = tmp("delete");
        let _ = std::fs::remove_file(&p);

        let mut t = BTree::create(&p).unwrap();
        t.put(b"k", b"v").unwrap();
        t.delete(b"k").unwrap();
        assert_eq!(t.get(b"k").unwrap(), None);

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn btree_overwrite_key() {
        let p = tmp("overwrite");
        let _ = std::fs::remove_file(&p);

        let mut t = BTree::create(&p).unwrap();
        t.put(b"k", b"v1").unwrap();
        t.put(b"k", b"v2").unwrap();
        assert_eq!(t.get(b"k").unwrap(), Some(b"v2".to_vec()));

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn btree_scan_sorted() {
        let p = tmp("scan");
        let _ = std::fs::remove_file(&p);

        let mut t = BTree::create(&p).unwrap();
        for i in (0u8..10).rev() {
            t.put(&[i], &[i * 2]).unwrap();
        }
        let pairs = t.scan_by_key(&[0u8], &[9u8]).unwrap();
        let keys: Vec<Vec<u8>> = pairs.iter().map(|(k, _)| k.clone()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "scan_by_key must return sorted results");

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn btree_splits_on_many_inserts() {
        let p = tmp("splits");
        let _ = std::fs::remove_file(&p);

        let mut t = BTree::create(&p).unwrap();
        // 500 inserts should force leaf splits and eventually internal page splits.
        for i in 0u32..500 {
            let k = format!("key{i:05}");
            let v = format!("val{i:05}");
            t.put(k.as_bytes(), v.as_bytes()).unwrap();
        }

        // Verify a sample.
        for i in [0u32, 1, 100, 250, 499] {
            let k = format!("key{i:05}");
            let v = format!("val{i:05}");
            assert_eq!(t.get(k.as_bytes()).unwrap(), Some(v.into_bytes()), "key {k}");
        }

        // Verify range scan returns sorted results.
        let start = b"key00100".as_ref();
        let end   = b"key00199".as_ref();
        let results = t.scan_by_key(start, end).unwrap();
        assert_eq!(results.len(), 100, "expected 100 results in range");
        let keys: Vec<_> = results.iter().map(|(k, _)| k.clone()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn btree_tree_height_is_log() {
        let p = tmp("height");
        let _ = std::fs::remove_file(&p);

        let mut t = BTree::create(&p).unwrap();
        let n: u32 = 1000;
        for i in 0..n {
            let k = format!("{i:08}");
            t.put(k.as_bytes(), b"v").unwrap();
        }

        // Max expected height for 1000 keys with branching factor ~100+ is 3.
        let height = tree_height(&t).unwrap();
        assert!(height <= 4, "tree height {height} exceeds expected bound");

        let _ = std::fs::remove_file(&p);
    }

    /// Walk from root to leftmost leaf, counting levels.
    fn tree_height(t: &BTree) -> Result<usize> {
        let mut pgno = t.pager.root_page();
        let mut h = 1;
        loop {
            let page_type = t.pager.with_page(pgno, |page| Ok(page[HDR_PAGE_TYPE]))?;
            if page_type == PAGE_TYPE_LEAF { break; }
            // Follow leftmost child.
            pgno = t.pager.with_page(pgno, |page| Ok(read_u64(page, HDR_LEFTMOST)))?;
            h += 1;
        }
        Ok(h)
    }

    // ── Property tests ────────────────────────────────────────────────────────

    use proptest::prelude::*;
    use crate::wal::wal_path;

    #[derive(Debug, Clone)]
    enum Op {
        Put(Vec<u8>, Vec<u8>),
        Delete(Vec<u8>),
    }

    fn arb_key() -> impl Strategy<Value = Vec<u8>> {
        // Narrow alphabet (0..16) forces frequent key reuse:
        // overwrites, deletes of existing keys, and eventually splits.
        prop::collection::vec(0u8..16, 1..=4)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn prop_btree_ops_invariants_always_hold(
            ops in prop::collection::vec(
                prop_oneof![
                    (arb_key(), prop::collection::vec(any::<u8>(), 1..=16))
                        .prop_map(|(k, v)| Op::Put(k, v)),
                    arb_key().prop_map(Op::Delete),
                ],
                1..=150,
            )
        ) {
            let p = tmp("proptest");
            let wp = wal_path(&p);
            let _ = std::fs::remove_file(&p);
            let _ = std::fs::remove_file(&wp);
            let mut t = BTree::create(&p).unwrap();
            let mut model: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = Default::default();

            for op in &ops {
                match op {
                    Op::Put(k, v) => {
                        t.put(k, v).unwrap();
                        model.insert(k.clone(), v.clone());
                    }
                    Op::Delete(k) => {
                        t.delete(k).unwrap();
                        model.remove(k);
                    }
                }
                prop_assert!(
                    t.check_invariants().is_ok(),
                    "check_invariants failed after {:?}", op
                );
            }

            // Final model comparison: scan_physical must match the BTreeMap reference.
            let expected: Vec<_> = model.into_iter().collect();
            let actual = t.scan_physical().unwrap();
            prop_assert_eq!(actual, expected, "scan_physical must match BTreeMap model after all ops");

            let _ = std::fs::remove_file(&p);
            let _ = std::fs::remove_file(&wp);
        }
    }

    // ── check_invariants tests ────────────────────────────────────────────────

    #[test]
    fn invariants_empty_tree() {
        let p = tmp("inv_empty");
        let _ = std::fs::remove_file(&p);
        let t = BTree::create(&p).unwrap();
        t.check_invariants().unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn invariants_small_tree() {
        let p = tmp("inv_small");
        let _ = std::fs::remove_file(&p);
        let mut t = BTree::create(&p).unwrap();
        for k in &[b"alpha" as &[u8], b"beta", b"gamma", b"delta", b"epsilon"] {
            t.put(k, b"v").unwrap();
        }
        t.check_invariants().unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn invariants_after_many_inserts_with_splits() {
        let p = tmp("inv_splits");
        let _ = std::fs::remove_file(&p);
        let mut t = BTree::create(&p).unwrap();
        for i in 0u32..500 {
            let k = format!("key{i:05}");
            let v = format!("val{i:05}");
            t.put(k.as_bytes(), v.as_bytes()).unwrap();
        }
        t.check_invariants().unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn invariants_after_reverse_order_inserts() {
        // Reverse insertion stresses the separator routing differently than forward order.
        let p = tmp("inv_reverse");
        let _ = std::fs::remove_file(&p);
        let mut t = BTree::create(&p).unwrap();
        for i in (0u32..300).rev() {
            let k = format!("{i:08}");
            t.put(k.as_bytes(), b"v").unwrap();
        }
        t.check_invariants().unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn invariants_after_delete() {
        let p = tmp("inv_delete");
        let _ = std::fs::remove_file(&p);
        let mut t = BTree::create(&p).unwrap();
        for i in 0u32..50 {
            let k = format!("k{i:03}");
            t.put(k.as_bytes(), b"v").unwrap();
        }
        // Delete every third key.
        for i in (0u32..50).step_by(3) {
            let k = format!("k{i:03}");
            t.delete(k.as_bytes()).unwrap();
        }
        t.check_invariants().unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn invariants_scan_matches_model() {
        // Verify that scan_physical() result matches an in-memory BTreeMap reference.
        let p = tmp("inv_model");
        let _ = std::fs::remove_file(&p);
        let mut model: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
        let mut t = BTree::create(&p).unwrap();
        for i in 0u32..200 {
            // Mix forward and reverse to exercise both split directions.
            let idx = if i % 2 == 0 { i } else { 400 - i };
            let k = format!("key{idx:05}").into_bytes();
            let v = format!("val{idx:05}").into_bytes();
            model.insert(k.clone(), v.clone());
            t.put(&k, &v).unwrap();
        }
        t.check_invariants().unwrap();
        let expected: Vec<_> = model.into_iter().collect();
        let actual = t.scan_physical().unwrap();
        assert_eq!(actual, expected, "scan_physical must match BTreeMap model");
        let _ = std::fs::remove_file(&p);
    }
}
