//! Length-limited Huffman code construction shared by the encoders (DEFLATE: 15 bits,
//! bzip2: 17 bits).
//!
//! [`huffman_lengths`]: optimal code lengths by the in-place Moffat-Katajainen algorithm on
//! the sorted weights, then over-long codes are clamped and the Kraft sum repaired by
//! lengthening the deepest codes that still fit (the classic zlib/miniz heuristic; within a
//! fraction of a percent of package-merge on real data and O(n)).

/// In-place minimum-redundancy code lengths (Moffat & Katajainen): `a` holds the symbol
/// weights sorted ascending (n >= 2) and is overwritten with their code lengths.
pub(crate) fn minimum_redundancy(a: &mut [u32]) {
    let n = a.len();
    debug_assert!(n >= 2);
    // Phase 1: build the tree; internal node weights, then parent pointers.
    a[0] += a[1];
    let mut root = 0usize;
    let mut leaf = 2usize;
    for next in 1..n - 1 {
        if leaf >= n || a[root] < a[leaf] {
            a[next] = a[root];
            a[root] = next as u32;
            root += 1;
        } else {
            a[next] = a[leaf];
            leaf += 1;
        }
        if leaf >= n || (root < next && a[root] < a[leaf]) {
            a[next] += a[root];
            a[root] = next as u32;
            root += 1;
        } else {
            a[next] += a[leaf];
            leaf += 1;
        }
    }
    // Phase 2: internal node depths.
    a[n - 2] = 0;
    for next in (0..n - 2).rev() {
        a[next] = a[a[next] as usize] + 1;
    }
    // Phase 3: leaf depths.
    let mut avail = 1usize;
    let mut used = 0usize;
    let mut depth = 0u32;
    let mut root = n as isize - 2;
    let mut next = n as isize - 1;
    while avail > 0 {
        while root >= 0 && a[root as usize] == depth {
            used += 1;
            root -= 1;
        }
        while avail > used {
            a[next as usize] = depth;
            next -= 1;
            avail -= 1;
        }
        avail = 2 * used;
        depth += 1;
        used = 0;
    }
}

/// Length-limited (`max_len` <= 24) Huffman code lengths for `freqs` (unused symbols get 0).
/// The code is always complete with at least two symbols (a dummy symbol is added if fewer
/// are used), which every inflater accepts.
pub(crate) fn huffman_lengths(freqs: &[u32], max_len: u32, lens: &mut [u8]) {
    let n = freqs.len();
    debug_assert!(n <= 320 && lens.len() >= n && n >= 2 && max_len <= 24);
    lens[..n].fill(0);
    let mut keys = [0u64; 320];
    let mut cnt = 0;
    for (s, &f) in freqs.iter().enumerate() {
        if f != 0 {
            keys[cnt] = ((f as u64) << 16) | s as u64;
            cnt += 1;
        }
    }
    if cnt < 2 {
        let s = if cnt == 1 { (keys[0] & 0xFFFF) as usize } else { 0 };
        lens[s] = 1;
        lens[if s == 0 { 1 } else { 0 }] = 1;
        return;
    }
    let keys = &mut keys[..cnt];
    keys.sort_unstable();
    let mut a = [0u32; 320];
    for (x, k) in a.iter_mut().zip(keys.iter()) {
        *x = (k >> 16) as u32;
    }
    minimum_redundancy(&mut a[..cnt]);
    // Count leaves per length, clamping over-long codes, then repair the Kraft sum.
    let mut bl = [0u32; 32];
    for &d in &a[..cnt] {
        bl[d.min(max_len) as usize] += 1;
    }
    let mut total: u32 = 0;
    for l in 1..=max_len {
        total += bl[l as usize] << (max_len - l);
    }
    while total > 1 << max_len {
        bl[max_len as usize] -= 1;
        for l in (1..max_len as usize).rev() {
            if bl[l] != 0 {
                bl[l] -= 1;
                bl[l + 1] += 2;
                break;
            }
        }
        total -= 1;
    }
    // Most frequent symbols (end of `keys`) get the shortest codes.
    let mut i = cnt;
    for l in 1..=max_len as usize {
        for _ in 0..bl[l] {
            i -= 1;
            lens[(keys[i] & 0xFFFF) as usize] = l as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codecs_huffman_enc_lengths() {
        // Skewed (Fibonacci) frequencies force the length limit.
        let mut f = [0u32; 40];
        let (mut a, mut b) = (1u32, 1u32);
        for x in f.iter_mut() {
            *x = a;
            let c = a.saturating_add(b);
            a = b;
            b = c;
        }
        for max in [7u32, 9, 15] {
            let mut lens = [0u8; 40];
            huffman_lengths(&f, max, &mut lens);
            let kraft: f64 = lens.iter().filter(|&&l| l > 0).map(|&l| 0.5f64.powi(l as i32)).sum();
            assert!((kraft - 1.0).abs() < 1e-12, "max {max}: kraft {kraft}");
            assert!(lens.iter().all(|&l| l >= 1 && l as u32 <= max));
        }
        let mut lens = [0u8; 4];
        huffman_lengths(&[0, 0, 5, 0], 15, &mut lens);
        assert_eq!(lens.iter().filter(|&&l| l == 1).count(), 2);
    }

    #[test]
    fn codecs_huffman_enc_long_codes() {
        let mut f = [0u32; 258];
        let (mut a, mut b) = (1u32, 1u32);
        for x in f.iter_mut() {
            *x = a;
            let c = a.saturating_add(b);
            a = b;
            b = c;
        }
        let mut lens = [0u8; 258];
        huffman_lengths(&f, 17, &mut lens);
        assert!(lens.iter().all(|&l| (1..=17).contains(&l)));
        let kraft: f64 = lens.iter().map(|&l| 0.5f64.powi(l as i32)).sum();
        assert!((kraft - 1.0).abs() < 1e-12);
    }
}
