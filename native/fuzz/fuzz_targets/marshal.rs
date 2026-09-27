// SPDX-License-Identifier: Apache-2.0
//! Fuzz the pointer marshalling.
//!
//! This is the code that reads memory the caller describes rather than memory
//! it owns, so it is where a mistake stops being a wrong answer and becomes an
//! out-of-bounds read. The interesting inputs are not the paths themselves but
//! the shapes around them: a count that disagrees with the array, a null where
//! a string was promised, bytes that are not text.
//!
//! What is deliberately not fuzzed is a count *larger* than the array. The C
//! ABI contract says every pointer is valid for its stated length; a caller
//! that lies about that is describing memory it does not have, and no amount
//! of checking on this side can make that safe. Fuzzing it would only prove
//! that reading unallocated memory reads unallocated memory.

#![no_main]

use arbitrary::Arbitrary;
use hlyn::marshal;
use libfuzzer_sys::fuzz_target;
use std::ffi::c_char;

#[derive(Arbitrary, Debug)]
struct Input {
    items: Vec<Vec<u8>>,
    ports: Vec<u16>,
    /// How many of the entries to claim, before clamping to what exists.
    claim: usize,
    /// Replace one entry with a null pointer, as a caller with a gap would.
    hole: Option<usize>,
    /// Describe entries that are not there at all.
    empty_array: bool,
}

fuzz_target!(|input: Input| {
    // A C string cannot contain an interior NUL, so those bytes are dropped
    // rather than rejected: the point is to reach the UTF-8 check with hostile
    // bytes, not to test CString's own validation.
    let owned: Vec<Vec<u8>> = input
        .items
        .iter()
        .map(|item| {
            let mut bytes: Vec<u8> = item.iter().copied().filter(|&b| b != 0).collect();
            bytes.push(0);
            bytes
        })
        .collect();

    let mut pointers: Vec<*const c_char> =
        owned.iter().map(|b| b.as_ptr() as *const c_char).collect();
    if let Some(at) = input.hole {
        let len = pointers.len();
        if len != 0 {
            pointers[at % len] = std::ptr::null();
        }
    }

    let count = input.claim.min(pointers.len());
    let items = if input.empty_array {
        std::ptr::null()
    } else {
        pointers.as_ptr()
    };
    // A null array with a non-zero count is in contract: it is the shape ctypes
    // produces for an empty list, and the code answers it without reading.
    let got = unsafe { marshal::strings(items, if input.empty_array { input.claim } else { count }) };

    // Whatever comes back must be exactly what was asked for, or nothing. A
    // short read would mean granting fewer paths than the caller named while
    // reporting full enforcement.
    if let Some(paths) = got {
        assert_eq!(paths.len(), count);
        assert!(!input.empty_array || count == 0);
    }

    let numbers = input.ports.clone();
    let claim = input.claim.min(numbers.len());
    let got = unsafe { marshal::ports(numbers.as_ptr(), claim) };
    assert_eq!(got, Some(numbers[..claim].to_vec()));

    assert_eq!(unsafe { marshal::ports(std::ptr::null(), 0) }, Some(Vec::new()));
});
