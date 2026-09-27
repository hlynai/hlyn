// SPDX-License-Identifier: Apache-2.0
//! Counting repeats, so a retry loop is one record rather than a million.
//!
//! A refusal is sent on its 1st, 2nd, 4th, 8th ... occurrence and counted in
//! between, the same rule the Python log uses. The reader keeps the largest
//! count it sees, so the total stays roughly right while a program that hits
//! the same wall a million times costs about twenty writes.
//!
//! Lock-free and fixed-size: a table of atomics, claimed by compare-and-swap.
//! Safe from any thread, a signal handler, or a `vfork` child. When the table
//! is full, refusals go untracked and are sent every time -- more noise, never
//! less information.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const SLOTS: usize = 1024; // a power of two, so masking replaces modulo
const PROBE: usize = 16;

#[cfg_attr(test, allow(dead_code))]
static KEYS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
#[cfg_attr(test, allow(dead_code))]
static COUNTS: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];

/// How many times `key` has now been seen, or 0 if the table had no room.
#[cfg_attr(test, allow(dead_code))]
pub fn bump(key: u64) -> u32 {
    bump_in(&KEYS, &COUNTS, key)
}

fn bump_in(keys: &[AtomicU64; SLOTS], counts: &[AtomicU32; SLOTS], key: u64) -> u32 {
    let key = if key == 0 { 1 } else { key }; // 0 marks an empty slot
    let first = key as usize & (SLOTS - 1);
    for step in 0..PROBE {
        let slot = (first + step) & (SLOTS - 1);
        match keys[slot].compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return counts[slot].fetch_add(1, Ordering::AcqRel).saturating_add(1),
            Err(found) if found == key => {
                return counts[slot].fetch_add(1, Ordering::AcqRel).saturating_add(1)
            }
            Err(_) => continue,
        }
    }
    0
}

/// Whether the `count`th occurrence is one to send.
pub fn due(count: u32) -> bool {
    count == 0 || count.is_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn table() -> (Box<[AtomicU64; SLOTS]>, Box<[AtomicU32; SLOTS]>) {
        (
            Box::new([const { AtomicU64::new(0) }; SLOTS]),
            Box::new([const { AtomicU32::new(0) }; SLOTS]),
        )
    }

    #[test]
    fn repeats_are_sent_at_powers_of_two() {
        let (k, c) = table();
        let sent: Vec<u32> = (0..1000).map(|_| bump_in(&k, &c, 42)).filter(|&n| due(n)).collect();
        assert_eq!(sent, vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512]);
    }

    #[test]
    fn distinct_keys_count_separately() {
        let (k, c) = table();
        assert_eq!(bump_in(&k, &c, 1), 1);
        assert_eq!(bump_in(&k, &c, 2), 1);
        assert_eq!(bump_in(&k, &c, 1), 2);
        // Zero is the empty marker, so it shares a slot with 1 rather than
        // corrupting the table.
        assert_eq!(bump_in(&k, &c, 0), 3);
    }

    #[test]
    fn a_full_neighbourhood_stops_tracking_instead_of_failing() {
        let (k, c) = table();
        // Every key lands on the same first slot, so PROBE of them fill it.
        for i in 0..PROBE as u64 {
            assert_eq!(bump_in(&k, &c, 7 + i * SLOTS as u64), 1);
        }
        let overflow = 7 + PROBE as u64 * SLOTS as u64;
        assert_eq!(bump_in(&k, &c, overflow), 0);
        assert!(due(0), "untracked refusals are always sent");
    }

    #[test]
    fn threads_never_lose_a_count() {
        let (k, c) = table();
        let (k, c) = (Arc::new(*k), Arc::new(*c));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let (k, c) = (k.clone(), c.clone());
                std::thread::spawn(move || {
                    for key in 1..=50u64 {
                        for _ in 0..100 {
                            bump_in(&k, &c, key);
                        }
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        for key in 1..=50u64 {
            assert_eq!(bump_in(&k, &c, key), 801);
        }
    }
}
