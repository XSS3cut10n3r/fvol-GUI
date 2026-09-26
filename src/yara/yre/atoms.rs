//! Atom extraction for YARA regex / hex strings, reproducing libyara's atoms.c:
//! the atom tree (OR of literal runs, AND for alternations), the sliding 4-byte
//! window with the heuristic quality, trimming of wildcard edges, the choice of the
//! best combination, and the wildcard / wide / nocase expansions. Which atoms are
//! chosen determines where libyara splits the forward / backward matching, so this
//! is required for identical results, not just for speed.

use super::ast::{Ast, Kind, Node};

pub const MAX_ATOM_LENGTH: usize = 4;
pub const MAX_ATOM_QUALITY: i32 = 255;
pub const MIN_ATOM_QUALITY: i32 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Atom {
    pub bytes: [u8; MAX_ATOM_LENGTH],
    pub mask: [u8; MAX_ATOM_LENGTH],
    pub len: usize,
}

/// yr_atoms_heuristic_quality
pub fn quality(a: &Atom) -> i32 {
    let mut seen = [false; 256];
    let mut q: i32 = 0;
    let mut unique = 0;
    for i in 0..a.len.min(MAX_ATOM_LENGTH) {
        match a.mask[i] {
            0x00 => q -= 10,
            0x0f | 0xf0 => q += 4,
            0xff => {
                let b = a.bytes[i];
                q += match b {
                    0x00 | 0x20 | 0xcc | 0xff => 12,
                    _ => {
                        let l = b.to_ascii_lowercase();
                        if l.is_ascii_lowercase() { 18 } else { 20 }
                    }
                };
                if !seen[b as usize] {
                    seen[b as usize] = true;
                    unique += 1;
                }
            }
            _ => {}
        }
    }
    if unique == 1 && (seen[0x00] || seen[0x20] || seen[0x90] || seen[0xcc] || seen[0xff]) {
        q -= 10 * a.len as i32;
    } else {
        q += 2 * unique;
    }
    MAX_ATOM_QUALITY - 22 * MAX_ATOM_LENGTH as i32 + q
}

/// _yr_atoms_trim: returns the number of bytes trimmed from the left.
pub fn trim(a: &mut Atom) -> usize {
    let mut trim_left = 0;
    while trim_left < a.len && a.mask[trim_left] == 0 {
        trim_left += 1;
    }
    while a.len > trim_left && a.mask[a.len - 1] == 0 {
        a.len -= 1;
    }
    a.len -= trim_left;
    if a.len == 0 {
        return 0;
    }
    let mut mask_ff = 0;
    let mut mask_00 = 0;
    for i in 0..a.len {
        match a.mask[trim_left + i] {
            0xff => mask_ff += 1,
            0x00 => mask_00 += 1,
            _ => {}
        }
    }
    if mask_00 >= mask_ff {
        a.len = 1;
    }
    if trim_left == 0 {
        return 0;
    }
    for i in 0..MAX_ATOM_LENGTH - trim_left {
        a.bytes[i] = a.bytes[trim_left + i];
        a.mask[i] = a.mask[trim_left + i];
    }
    trim_left
}

/// A chosen atom: bytes + the RE node whose code the forward / backward programs
/// start from.
#[derive(Clone, Debug)]
pub struct ChosenAtom {
    pub atom: Atom,
    /// Node id (None for the zero-length "match everywhere" atom).
    pub node: Option<u32>,
    pub backtrack: usize,
}

enum TNode {
    Leaf { atom: Atom, nodes: Vec<u32> },
    Or(Vec<usize>),
    And(Vec<usize>),
}

struct Tree {
    nodes: Vec<TNode>,
}

impl Tree {
    fn add(&mut self, n: TNode) -> usize {
        self.nodes.push(n);
        self.nodes.len() - 1
    }
    fn append(&mut self, parent: usize, child: usize) {
        match &mut self.nodes[parent] {
            TNode::Or(v) | TNode::And(v) => v.push(child),
            TNode::Leaf { .. } => {}
        }
    }
}

struct Lit {
    id: u32,
    value: u8,
    mask: u8,
}

fn make_atom(recent: &[Lit]) -> Atom {
    let mut a = Atom::default();
    a.len = recent.len().min(MAX_ATOM_LENGTH);
    for i in 0..a.len {
        a.bytes[i] = recent[i].value;
        a.mask[i] = recent[i].mask;
    }
    a
}

/// _yr_atoms_extract_from_re: build the atom tree.
fn extract_tree(ast: &Ast) -> Tree {
    let mut t = Tree { nodes: Vec::new() };
    let root = t.add(TNode::Or(Vec::new()));
    // stack items: (node, new appending node)
    let mut stack: Vec<(Option<&Node>, Option<usize>)> = vec![(None, Some(root)), (Some(&ast.root), Some(root))];
    let mut recent: Vec<Lit> = Vec::with_capacity(MAX_ATOM_LENGTH);
    let mut best_atom = Atom::default();
    let mut best_nodes: Vec<u32> = Vec::new();
    let mut best_quality: i32 = -1;
    let mut current: usize = root;
    while let Some((node, new_app)) = stack.pop() {
        if let Some(na) = new_app {
            if !recent.is_empty() {
                let mut atom = make_atom(&recent);
                let shift = trim(&mut atom);
                let q = quality(&atom);
                let leaf = if q > best_quality {
                    TNode::Leaf { atom, nodes: recent[shift.min(recent.len())..].iter().map(|l| l.id).collect() }
                } else {
                    TNode::Leaf { atom: best_atom, nodes: best_nodes.clone() }
                };
                let li = t.add(leaf);
                t.append(current, li);
                recent.clear();
            }
            current = na;
            best_quality = -1;
        }
        let Some(n) = node else { continue };
        match &n.kind {
            Kind::Literal | Kind::MaskedLiteral | Kind::Any => {
                let lit = Lit { id: n.id, value: n.value, mask: n.mask };
                if recent.len() < MAX_ATOM_LENGTH {
                    let k = recent.len();
                    if best_nodes.len() <= k {
                        best_nodes.resize(k + 1, 0);
                    }
                    best_nodes[k] = lit.id;
                    best_nodes.truncate(k + 1);
                    best_atom.bytes[k] = lit.value;
                    best_atom.mask[k] = lit.mask;
                    best_atom.len = k + 1;
                    recent.push(lit);
                } else if best_quality < MAX_ATOM_QUALITY {
                    let mut atom = make_atom(&recent);
                    let shift = trim(&mut atom);
                    let q = quality(&atom);
                    if q > best_quality {
                        best_atom = Atom::default();
                        best_nodes.clear();
                        for i in 0..atom.len {
                            best_atom.bytes[i] = atom.bytes[i];
                            best_atom.mask[i] = atom.mask[i];
                            best_nodes.push(recent.get(i + shift).map_or(0, |l| l.id));
                        }
                        best_atom.len = atom.len;
                        best_quality = q;
                    }
                    recent.remove(0);
                    recent.push(lit);
                }
            }
            Kind::Concat(v) => {
                for c in v.iter().rev() {
                    stack.push((Some(c), None));
                }
            }
            Kind::Alt(a, b) => {
                let left = t.add(TNode::Or(Vec::new()));
                let right = t.add(TNode::Or(Vec::new()));
                let and = t.add(TNode::And(vec![left, right]));
                t.append(current, and);
                stack.push((None, Some(current)));
                stack.push((Some(b), Some(right)));
                stack.push((Some(a), Some(left)));
            }
            Kind::Plus(c) => {
                stack.push((None, Some(current)));
                stack.push((Some(c), None));
            }
            Kind::Range(c) => {
                stack.push((None, Some(current)));
                for _ in 0..(n.start.max(0) as usize).min(MAX_ATOM_LENGTH) {
                    stack.push((Some(c), None));
                }
            }
            _ => stack.push((None, Some(current))),
        }
    }
    t
}

/// _yr_atoms_choose
fn choose(t: &Tree, i: usize, out: &mut Vec<ChosenAtom>) -> i32 {
    match &t.nodes[i] {
        TNode::Leaf { atom, nodes } => {
            let mut a = *atom;
            let shift = trim(&mut a);
            if a.len > 0 {
                out.push(ChosenAtom { atom: a, node: nodes.get(shift).copied(), backtrack: 0 });
                quality(&a)
            } else {
                MIN_ATOM_QUALITY
            }
        }
        TNode::Or(children) => {
            let mut max_q = MIN_ATOM_QUALITY;
            let mut chosen: Vec<ChosenAtom> = Vec::new();
            for &c in children {
                let mut item = Vec::new();
                let q = choose(t, c, &mut item);
                if q > max_q {
                    max_q = q;
                    chosen = item;
                }
                if max_q == MAX_ATOM_QUALITY {
                    break;
                }
            }
            out.extend(chosen);
            max_q
        }
        TNode::And(children) => {
            let mut min_q = MAX_ATOM_QUALITY;
            let mut acc: Vec<ChosenAtom> = Vec::new();
            for &c in children {
                let mut item = Vec::new();
                let q = choose(t, c, &mut item);
                if q < min_q {
                    min_q = q;
                }
                // libyara prepends each child's list
                item.extend(acc);
                acc = item;
            }
            out.extend(acc);
            min_q
        }
    }
}

fn expand_wildcards(list: Vec<ChosenAtom>) -> Vec<ChosenAtom> {
    let mut out = Vec::new();
    for a in list {
        let mut cur = vec![a];
        for i in 0..MAX_ATOM_LENGTH {
            if cur.first().map_or(true, |x| i >= x.atom.len) {
                break;
            }
            let mut next = Vec::with_capacity(cur.len());
            for x in cur {
                let (s, e, incr): (u16, u16, u16) = match x.atom.mask[i] {
                    0x00 => (0, 0xff, 1),
                    0x0f => (x.atom.bytes[i] as u16, (x.atom.bytes[i] | 0xf0) as u16, 0x10),
                    0xf0 => (x.atom.bytes[i] as u16, (x.atom.bytes[i] | 0x0f) as u16, 1),
                    _ => (0, 0, 1),
                };
                if s == e {
                    let mut y = x.clone();
                    y.atom.mask[i] = 0xff;
                    next.push(y);
                    continue;
                }
                let mut v = s;
                while v <= e {
                    let mut y = x.clone();
                    y.atom.bytes[i] = v as u8;
                    y.atom.mask[i] = 0xff;
                    next.push(y);
                    v += incr;
                }
            }
            cur = next;
        }
        out.extend(cur);
    }
    out
}

fn wide(list: &[ChosenAtom]) -> Vec<ChosenAtom> {
    let mut out: Vec<ChosenAtom> = list
        .iter()
        .map(|a| {
            let mut w = a.clone();
            w.atom.bytes = [0; MAX_ATOM_LENGTH];
            w.atom.mask = [0xff; MAX_ATOM_LENGTH];
            for i in 0..a.atom.len {
                if i * 2 < MAX_ATOM_LENGTH {
                    w.atom.bytes[i * 2] = a.atom.bytes[i];
                } else {
                    break;
                }
            }
            w.atom.len = (a.atom.len * 2).min(MAX_ATOM_LENGTH);
            w.backtrack = a.backtrack * 2;
            w
        })
        .collect();
    out.reverse(); // libyara builds the list by prepending
    out
}

fn case_combinations(list: &[ChosenAtom]) -> Vec<ChosenAtom> {
    let mut out = Vec::new();
    for a in list {
        let letters: Vec<usize> = (0..a.atom.len).filter(|&i| a.atom.bytes[i].is_ascii_alphabetic()).collect();
        let k = letters.len();
        for m in 0..(1u32 << k) {
            let mut y = a.clone();
            for (bit, &i) in letters.iter().enumerate() {
                if m >> bit & 1 != 0 {
                    y.atom.bytes[i] ^= 0x20;
                }
            }
            y.atom.mask = [0xff; MAX_ATOM_LENGTH];
            out.push(y);
        }
    }
    out
}

/// yr_atoms_extract_from_re. Returns the chosen atoms (possibly empty = caller adds a
/// zero-length atom at the forward code start).
pub fn from_re(ast: &Ast, is_wide: bool, is_ascii: bool, nocase: bool) -> Vec<ChosenAtom> {
    let t = extract_tree(ast);
    let mut chosen = Vec::new();
    choose(&t, 0, &mut chosen);
    let mut atoms = expand_wildcards(chosen);
    if is_wide {
        let w = wide(&atoms);
        if is_ascii {
            atoms.extend(w);
        } else {
            atoms = w;
        }
    }
    if nocase {
        let ci = case_combinations(&atoms);
        atoms.extend(ci);
    }
    atoms
}

/// yr_atoms_extract_from_string (for hex / regex strings that are plain literals).
pub fn from_literal(s: &[u8], is_wide: bool, is_ascii: bool, nocase: bool) -> Vec<ChosenAtom> {
    let mut item = ChosenAtom { atom: Atom::default(), node: None, backtrack: 0 };
    item.atom.len = s.len().min(MAX_ATOM_LENGTH);
    for i in 0..item.atom.len {
        item.atom.bytes[i] = s[i];
        item.atom.mask[i] = 0xff;
    }
    let mut max_q = quality(&item.atom);
    let mut i = MAX_ATOM_LENGTH;
    while i < s.len() && max_q < MAX_ATOM_QUALITY {
        let mut a = Atom { len: MAX_ATOM_LENGTH, mask: [0xff; MAX_ATOM_LENGTH], ..Default::default() };
        a.bytes.copy_from_slice(&s[i + 1 - MAX_ATOM_LENGTH..i + 1]);
        let q = quality(&a);
        if q > max_q {
            item.atom = a;
            item.backtrack = i + 1 - MAX_ATOM_LENGTH;
            max_q = q;
        }
        i += 1;
    }
    let mut atoms = vec![item];
    if is_wide {
        let w = wide(&atoms);
        if is_ascii {
            atoms.extend(w);
        } else {
            atoms = w;
        }
    }
    if nocase {
        let ci = case_combinations(&atoms);
        atoms.extend(ci);
    }
    atoms
}
