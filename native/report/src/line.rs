// SPDX-License-Identifier: Apache-2.0
//! One record, built in a fixed buffer.
//!
//! ```text
//! hlyn1 <TAB> kind <TAB> op <TAB> errno <TAB> target <TAB> pid <TAB> comm <TAB> cut <TAB> count <LF>
//! ```
//!
//! Every field that can hold outside bytes (`comm`, `target`) is escaped: bytes
//! below 0x20, 0x7f and `%` become `%XX`, so a record is always exactly one
//! line with exactly nine fields, whatever a path contains. Anything else,
//! including non-UTF-8, passes through; the reader decides how to show it.

/// A write of at most `PIPE_BUF` bytes to a pipe is never interleaved with
/// another writer's, which is what lets every process in the tree share one
/// pipe without a lock.
pub const CAP: usize = 4096;

/// Kept free while writing the target, for the fields that follow it: a tab,
/// a pid (10 digits), a tab, a name (16 bytes, up to 48 escaped), and `TAIL`.
const ROOM: usize = 96;

/// Kept free for the last fields: tab, cut flag, tab, count (10), newline.
const TAIL: usize = 16;

pub struct Line {
    buf: [u8; CAP],
    len: usize,
    limit: usize,
    start: usize,
    end: usize,
    inside: bool,
    cut: bool,
}

impl Line {
    pub const fn new() -> Self {
        Line { buf: [0; CAP], len: 0, limit: CAP - ROOM, start: 0, end: 0, inside: false, cut: false }
    }

    /// The finished record.
    pub fn bytes(&self) -> &[u8] {
        // `len` never exceeds CAP: every write below checks before it moves.
        let len = if self.len <= CAP { self.len } else { CAP };
        &self.buf[..len]
    }

    fn put(&mut self, byte: u8, limit: usize) -> bool {
        if self.len < limit && self.len < CAP {
            self.buf[self.len] = byte;
            self.len += 1;
            true
        } else {
            false
        }
    }

    /// Notes that the target was cut short, if that is what is being written.
    fn full(&mut self) {
        if self.inside {
            self.cut = true;
        }
    }

    /// Bytes known to need no escaping: the fixed names of this file.
    pub fn raw(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if !self.put(b, self.limit) {
                self.full();
                return;
            }
        }
    }

    /// Bytes from outside, escaped. Stops cleanly when the record is full.
    pub fn text(&mut self, bytes: &[u8]) {
        let limit = self.limit;
        for &b in bytes {
            if b < 0x20 || b == 0x7f || b == b'%' {
                if self.len + 3 > limit {
                    self.full();
                    return;
                }
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                self.put(b'%', limit);
                self.put(HEX[(b >> 4) as usize], limit);
                self.put(HEX[(b & 0xf) as usize], limit);
            } else if !self.put(b, limit) {
                self.full();
                return;
            }
        }
    }

    /// A NUL-terminated string from outside, read no further than `max` bytes.
    ///
    /// # Safety
    /// `ptr` must be null or point to memory readable up to its terminator or
    /// `max` bytes, whichever comes first.
    pub unsafe fn cstr(&mut self, ptr: *const u8, max: usize) {
        if ptr.is_null() {
            self.raw(b"?");
            return;
        }
        let mut n = 0;
        while n < max && *ptr.add(n) != 0 {
            n += 1;
        }
        self.text(core::slice::from_raw_parts(ptr, n));
    }

    pub fn num(&mut self, value: u64) {
        let mut digits = [0u8; 20];
        let mut n = 0;
        let mut v = value;
        loop {
            digits[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 || n == digits.len() {
                break;
            }
        }
        while n > 0 {
            n -= 1;
            self.put(digits[n], CAP);
        }
    }

    pub fn hex(&mut self, value: u16) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut started = false;
        for shift in [12u32, 8, 4, 0] {
            let d = ((value >> shift) & 0xf) as usize;
            if d != 0 || started || shift == 0 {
                started = true;
                self.put(HEX[d], self.limit);
            }
        }
    }

    pub fn tab(&mut self) {
        self.put(b'\t', CAP);
    }

    /// Marks where the target begins; everything up to `close` is its key.
    pub fn open(&mut self) {
        self.start = self.len;
        self.inside = true;
    }

    /// Marks where the target ends. What follows may use the room kept for it.
    pub fn close(&mut self) {
        self.end = self.len;
        self.inside = false;
        self.limit = CAP - TAIL;
    }

    /// Identifies this refusal for de-duplication: the kind and the target.
    pub fn key(&self, kind: &[u8]) -> u64 {
        // FNV-1a: stable, tiny, and more than good enough to tell a few
        // hundred distinct paths apart. Not a security property -- a collision
        // only merges two counts.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let end = if self.end <= self.len { self.end } else { self.len };
        let start = if self.start <= end { self.start } else { end };
        for &b in kind.iter().chain([0u8].iter()).chain(self.buf[start..end].iter()) {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        hash
    }

    /// Writes the trailing fields and the newline.
    pub fn finish(&mut self, count: u32) {
        self.tab();
        self.put(if self.cut { b'1' } else { b'0' }, CAP);
        self.tab();
        self.num(count as u64);
        self.put(b'\n', CAP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: &[u8]) -> Vec<u8> {
        let mut line = Line::new();
        line.text(bytes);
        line.bytes().to_vec()
    }

    #[test]
    fn plain_bytes_pass_through() {
        assert_eq!(text(b"/home/k/a b.txt"), b"/home/k/a b.txt");
        assert_eq!(text("/tmp/caf\u{e9}".as_bytes()), "/tmp/caf\u{e9}".as_bytes());
    }

    #[test]
    fn separators_and_controls_are_escaped() {
        assert_eq!(text(b"a\tb\nc%d\x1b[31m\x7f"), b"a%09b%0Ac%25d%1B[31m%7F");
    }

    #[test]
    fn a_huge_target_is_cut_and_the_record_still_fits() {
        let mut line = Line::new();
        line.raw(b"hlyn1\tread\topen\t13\t");
        line.open();
        line.text(&[b'%'; 10_000]);
        line.close();
        line.tab();
        line.num(u32::MAX as u64);
        line.tab();
        line.text(&[b'%'; 16]);
        line.finish(u32::MAX);
        let out = line.bytes();
        assert!(out.len() <= CAP);
        assert_eq!(out.last(), Some(&b'\n'));
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
        assert_eq!(out.iter().filter(|&&b| b == b'\t').count(), 8);
        let s = String::from_utf8_lossy(out);
        assert!(s.ends_with("\t1\t4294967295\n"), "{s}");
        // Never half an escape: a cut lands between whole `%XX` groups.
        let fields: Vec<&str> = s.split('\t').collect();
        assert_eq!(fields[4].len() % 3, 0);
        // And the fields after a full-length target are all still there.
        assert_eq!(fields[5], "4294967295");
        assert_eq!(fields[6], "%25".repeat(16));
    }

    #[test]
    fn a_long_name_after_a_short_target_is_not_a_cut_target() {
        let mut line = Line::new();
        line.open();
        line.text(b"/a");
        line.close();
        line.tab();
        line.text(&[b'\x01'; 16]);
        line.finish(1);
        assert!(String::from_utf8_lossy(line.bytes()).ends_with("\t0\t1\n"));
    }

    #[test]
    fn numbers_render_in_decimal() {
        for value in [0u64, 7, 10, 4096, u64::MAX] {
            let mut line = Line::new();
            line.num(value);
            assert_eq!(line.bytes(), value.to_string().as_bytes());
        }
    }

    #[test]
    fn hex_groups_drop_leading_zeros() {
        for (value, want) in [(0u16, "0"), (1, "1"), (0x0db8, "db8"), (0xffff, "ffff")] {
            let mut line = Line::new();
            line.hex(value);
            assert_eq!(line.bytes(), want.as_bytes());
        }
    }

    #[test]
    fn the_key_depends_on_kind_and_target_only() {
        let make = |kind: &[u8], pid: &[u8], target: &[u8]| {
            let mut line = Line::new();
            line.raw(pid);
            line.open();
            line.text(target);
            line.close();
            line.key(kind)
        };
        assert_eq!(make(b"read", b"1", b"/a"), make(b"read", b"2", b"/a"));
        assert_ne!(make(b"read", b"1", b"/a"), make(b"write", b"1", b"/a"));
        assert_ne!(make(b"read", b"1", b"/a"), make(b"read", b"1", b"/b"));
    }

    #[test]
    fn a_missing_string_is_a_question_mark() {
        let mut line = Line::new();
        unsafe { line.cstr(core::ptr::null(), 10) };
        assert_eq!(line.bytes(), b"?");
    }

    #[test]
    fn a_string_is_read_no_further_than_asked() {
        let bytes = *b"abcdef";
        let mut line = Line::new();
        unsafe { line.cstr(bytes.as_ptr(), 3) };
        assert_eq!(line.bytes(), b"abc");
    }
}
