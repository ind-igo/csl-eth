//! Pages, core §3.2, in both layouts.
//!
//! ```text
//! Page { n: u16, lo: [u8; 32], hi: [u8; 32], offsets: u16[n] (variable only), entries: Entry[n], zeros to 4096 }
//! Entry  = key[32] ‖ tag: u8 ‖ body
//!   tag 0  fixed:    body = value[value_size]
//!          variable: body = len: u16 ‖ value[len]
//!   tag 1  body empty
//!   tag 2  variable only: body = blake3(value)[32], bytes at blobs/<hash>
//! ```
//!
//! Packing is maximal and canonical. Fixed: every page except the last
//! holds exactly `entries_per_page(value_size)` entries, tombstones included
//! (they occupy an entry slot even though their body is empty). Variable:
//! entries are placed greedily in key order while
//! `66 + 2n + Σ entry bytes ≤ 4096`, and a new page starts at the first
//! entry that does not fit. Fences chain: `lo(1) = 0^32`,
//! `hi(i) = lo(i + 1) = first key of page i + 1`, `hi(last) = 0xFF^32` and
//! inclusive on that page only.

use crate::{EntryLayout, Error, KEY, KEY_MAX, PAGE, PAGE_HEADER};

/// The longest tag 0 value the variable layout places inline: one entry
/// alone on a page, `4096 − 66 − 2 − 32 − 1 − 2`. A profile's blob threshold
/// must not exceed it (core §3.2 says 3968, which is safely below).
pub const MAX_INLINE_VALUE: usize = PAGE - PAGE_HEADER - 2 - KEY - 1 - 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: [u8; KEY],
    /// 0 value, 1 tombstone, 2 blob (variable layout only).
    pub tag: u8,
    /// Tag 0: the value (`value_size` bytes in the fixed layout). Tag 1:
    /// empty. Tag 2: the 32-byte `blake3` of the value.
    pub value: Vec<u8>,
}

impl Entry {
    pub fn value(key: [u8; KEY], value: Vec<u8>) -> Entry {
        Entry { key, tag: 0, value }
    }
    pub fn tombstone(key: [u8; KEY]) -> Entry {
        Entry { key, tag: 1, value: Vec::new() }
    }
    pub fn blob(key: [u8; KEY], hash: [u8; 32]) -> Entry {
        Entry { key, tag: 2, value: hash.to_vec() }
    }

    /// Validity in the fixed layout: tag 0 of `value_size` bytes or tag 1.
    pub fn check(&self, value_size: u32) -> Result<(), Error> {
        self.check_layout(EntryLayout::Fixed { value_size })
    }

    pub fn check_layout(&self, layout: EntryLayout) -> Result<(), Error> {
        let len = self.value.len();
        let want = |expected: usize| {
            if len == expected {
                Ok(())
            } else {
                Err(Error::BadValueLen { expected, got: len })
            }
        };
        match (layout, self.tag) {
            (EntryLayout::Fixed { value_size }, 0) => want(value_size as usize),
            (EntryLayout::Variable, 0) if len <= MAX_INLINE_VALUE => Ok(()),
            (EntryLayout::Variable, 0) => Err(Error::BadValueLen { expected: MAX_INLINE_VALUE, got: len }),
            (_, 1) => want(0),
            (EntryLayout::Variable, 2) => want(32),
            (_, t) => Err(Error::BadTag(t)),
        }
    }

    /// Bytes this entry takes in a page of the given layout, offset
    /// excluded.
    pub fn encoded_len(&self, layout: EntryLayout) -> usize {
        KEY + 1
            + match (layout, self.tag) {
                (EntryLayout::Variable, 0) => 2 + self.value.len(),
                _ => self.value.len(),
            }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub lo: [u8; KEY],
    pub hi: [u8; KEY],
    pub entries: Vec<Entry>,
}

/// `floor(4030 / (33 + value_size))`.
pub fn entries_per_page(value_size: u32) -> usize {
    pgm::entries_per_page(value_size) as usize
}

/// Variable layout: do `n` entries totalling `bytes` fit on one page with
/// their offsets?
pub fn variable_fits(n: usize, bytes: usize) -> bool {
    PAGE_HEADER + 2 * n + bytes <= PAGE
}

impl Page {
    /// Is `key` inside this page's fence range? `last` makes `hi` inclusive.
    pub fn covers(&self, key: &[u8; KEY], last: bool) -> bool {
        *key >= self.lo && (*key < self.hi || (last && *key <= self.hi))
    }

    pub fn find(&self, key: &[u8; KEY]) -> Option<&Entry> {
        self.entries.binary_search_by(|e| e.key.cmp(key)).ok().map(|i| &self.entries[i])
    }

    /// Fixed layout.
    pub fn encode(&self) -> [u8; PAGE] {
        self.encode_with(EntryLayout::Fixed { value_size: 0 })
    }

    pub fn encode_with(&self, layout: EntryLayout) -> [u8; PAGE] {
        let mut out = [0u8; PAGE];
        let n = self.entries.len();
        out[0..2].copy_from_slice(&(n as u16).to_le_bytes());
        out[2..34].copy_from_slice(&self.lo);
        out[34..66].copy_from_slice(&self.hi);
        let variable = layout == EntryLayout::Variable;
        let mut o = PAGE_HEADER + if variable { 2 * n } else { 0 };
        for (i, e) in self.entries.iter().enumerate() {
            if variable {
                out[PAGE_HEADER + 2 * i..PAGE_HEADER + 2 * i + 2].copy_from_slice(&(o as u16).to_le_bytes());
            }
            out[o..o + KEY].copy_from_slice(&e.key);
            o += KEY;
            out[o] = e.tag;
            o += 1;
            if variable && e.tag == 0 {
                out[o..o + 2].copy_from_slice(&(e.value.len() as u16).to_le_bytes());
                o += 2;
            }
            out[o..o + e.value.len()].copy_from_slice(&e.value);
            o += e.value.len();
        }
        debug_assert!(o <= PAGE);
        out
    }

    /// Decode and validate a fixed-layout page. `last` relaxes the upper
    /// fence to inclusive.
    pub fn decode(bytes: &[u8], value_size: u32, last: bool, page_no: u64) -> Result<Page, Error> {
        Self::decode_with(bytes, EntryLayout::Fixed { value_size }, last, page_no)
    }

    /// Decode and validate a page. Everything the format fixes is checked:
    /// the count, the fences, the offsets (variable), entry order, every
    /// key inside the fences, tags and lengths, and zero padding, so a page
    /// is accepted only in its canonical encoding.
    pub fn decode_with(bytes: &[u8], layout: EntryLayout, last: bool, page_no: u64) -> Result<Page, Error> {
        let bad = |what: &'static str| Error::MalformedPage { page: page_no, what };
        if bytes.len() != PAGE {
            return Err(bad("length"));
        }
        let n = u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as usize;
        let variable = layout == EntryLayout::Variable;
        match layout {
            EntryLayout::Fixed { value_size } if n > entries_per_page(value_size) => return Err(bad("entry count")),
            EntryLayout::Variable if !variable_fits(n, n * (KEY + 1)) => return Err(bad("entry count")),
            _ => {}
        }
        let lo: [u8; KEY] = bytes[2..34].try_into().unwrap();
        let hi: [u8; KEY] = bytes[34..66].try_into().unwrap();
        if lo > hi || (!last && lo == hi) {
            return Err(bad("fence order"));
        }
        if last && hi != KEY_MAX {
            return Err(bad("last page hi"));
        }
        let mut entries = Vec::with_capacity(n);
        let mut o = PAGE_HEADER + if variable { 2 * n } else { 0 };
        let mut prev: Option<[u8; KEY]> = None;
        for i in 0..n {
            if variable {
                let off = u16::from_le_bytes(bytes[PAGE_HEADER + 2 * i..PAGE_HEADER + 2 * i + 2].try_into().unwrap()) as usize;
                if off != o {
                    return Err(bad("offsets"));
                }
            }
            if o + KEY + 1 > PAGE {
                return Err(bad("overflow"));
            }
            let key: [u8; KEY] = bytes[o..o + KEY].try_into().unwrap();
            o += KEY;
            let tag = bytes[o];
            o += 1;
            let body_len = match (layout, tag) {
                (EntryLayout::Fixed { value_size }, 0) => value_size as usize,
                (EntryLayout::Variable, 0) => {
                    if o + 2 > PAGE {
                        return Err(bad("overflow"));
                    }
                    let len = u16::from_le_bytes(bytes[o..o + 2].try_into().unwrap()) as usize;
                    o += 2;
                    if len > MAX_INLINE_VALUE {
                        return Err(bad("value length"));
                    }
                    len
                }
                (_, 1) => 0,
                (EntryLayout::Variable, 2) => 32,
                _ => return Err(bad("tag")),
            };
            if o + body_len > PAGE {
                return Err(bad("overflow"));
            }
            let value = bytes[o..o + body_len].to_vec();
            o += body_len;
            if let Some(p) = prev {
                if key <= p {
                    return Err(bad("entry order"));
                }
            }
            if key < lo || key > hi || (!last && key == hi) {
                return Err(bad("key outside fences"));
            }
            prev = Some(key);
            entries.push(Entry { key, tag, value });
        }
        if bytes[o..].iter().any(|&b| b != 0) {
            return Err(bad("padding"));
        }
        Ok(Page { lo, hi, entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KEY_MIN;

    fn k(b: u8) -> [u8; KEY] {
        let mut x = [0u8; KEY];
        x[0] = b;
        x
    }

    #[test]
    fn roundtrip_and_validation() {
        let p = Page { lo: KEY_MIN, hi: k(9), entries: vec![Entry::value(k(1), vec![7u8; 24]), Entry::tombstone(k(3)), Entry::value(k(8), vec![1u8; 24])] };
        let b = p.encode();
        assert_eq!(Page::decode(&b, 24, false, 1).unwrap(), p);
        assert!(p.covers(&k(8), false));
        assert!(!p.covers(&k(9), false));
        assert_eq!(p.find(&k(3)).unwrap().tag, 1);
        assert!(p.find(&k(4)).is_none());

        let mut bad = b;
        bad[PAGE - 1] = 1;
        assert!(matches!(Page::decode(&bad, 24, false, 1), Err(Error::MalformedPage { what: "padding", .. })));
        let mut bad = b;
        bad[34] = 0; // hi below the last key
        assert!(Page::decode(&bad, 24, false, 1).is_err());
    }

    #[test]
    fn last_page_is_inclusive() {
        let p = Page { lo: k(5), hi: KEY_MAX, entries: vec![Entry::value(KEY_MAX, vec![0u8; 24])] };
        let b = p.encode();
        assert_eq!(Page::decode(&b, 24, true, 3).unwrap(), p);
        assert!(Page::decode(&b, 24, false, 3).is_err());
        assert!(p.covers(&KEY_MAX, true));
    }

    #[test]
    fn epp() {
        assert_eq!(entries_per_page(24), 70);
        assert_eq!(PAGE_HEADER + 70 * 57, 4056);
    }

    #[test]
    fn variable_roundtrip_offsets_and_validation() {
        let v = EntryLayout::Variable;
        let p = Page {
            lo: KEY_MIN,
            hi: k(9),
            entries: vec![
                Entry::value(k(1), vec![7u8; 3]),
                Entry::tombstone(k(3)),
                Entry::blob(k(4), [0xBB; 32]),
                Entry::value(k(8), vec![]),
                Entry::value(
                    {
                        let mut x = k(8);
                        x[31] = 1;
                        x
                    },
                    vec![1u8; 500],
                ),
            ],
        };
        for e in &p.entries {
            e.check_layout(v).unwrap();
        }
        let b = p.encode_with(v);
        // Offsets: five of them after the header, the first pointing just past them.
        let first = u16::from_le_bytes(b[66..68].try_into().unwrap()) as usize;
        assert_eq!(first, PAGE_HEADER + 10);
        assert_eq!(Page::decode_with(&b, v, false, 1).unwrap(), p);
        // The sum of entry bytes is what the writer budgets.
        let total: usize = p.entries.iter().map(|e| e.encoded_len(v)).sum();
        assert_eq!(total, 38 + 33 + 65 + 35 + 535);
        assert!(variable_fits(5, total));

        // Fixed decode of a variable page fails, and vice versa.
        assert!(Page::decode(&b, 3, false, 1).is_err());
        assert!(Page::decode_with(&p.encode_with(EntryLayout::Fixed { value_size: 3 }), v, false, 1).is_err());

        // A shifted offset, a length past the page, a tag 2 in a fixed page.
        let mut bad = b;
        bad[68] ^= 1;
        assert!(matches!(Page::decode_with(&bad, v, false, 1), Err(Error::MalformedPage { what: "offsets", .. })));
        let mut bad = b;
        let len_at = first + KEY + 1;
        bad[len_at..len_at + 2].copy_from_slice(&4000u16.to_le_bytes());
        assert!(Page::decode_with(&bad, v, false, 1).is_err());
        assert!(matches!(Entry::blob(k(1), [0; 32]).check_layout(EntryLayout::Fixed { value_size: 32 }), Err(Error::BadTag(2))));
        assert!(matches!(Entry::value(k(1), vec![0; MAX_INLINE_VALUE + 1]).check_layout(v), Err(Error::BadValueLen { .. })));
        assert!(Entry::value(k(1), vec![0; MAX_INLINE_VALUE]).check_layout(v).is_ok());
    }

    #[test]
    fn one_maximal_value_fills_a_page_exactly() {
        let e = Entry::value(k(1), vec![9u8; MAX_INLINE_VALUE]);
        let v = EntryLayout::Variable;
        assert!(variable_fits(1, e.encoded_len(v)));
        assert!(!variable_fits(1, e.encoded_len(v) + 1));
        let p = Page { lo: KEY_MIN, hi: KEY_MAX, entries: vec![e] };
        let b = p.encode_with(v);
        assert_eq!(b[PAGE - 1], 9, "no padding left");
        assert_eq!(Page::decode_with(&b, v, true, 1).unwrap(), p);
    }
}
