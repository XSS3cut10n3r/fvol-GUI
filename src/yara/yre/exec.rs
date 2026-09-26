//! Executors for emitted YARA regex code, reproducing libyara 4.5 exactly:
//! * `exec`: the fiber machine of `yr_re_exec` (priority-ordered fibers, splits with
//!   per-sync split-id loop protection, repeat counters, repeat-any spinning, fiber
//!   dedupe, kill-tail on match / exhaustive callbacks for backward matching,
//!   YR_RE_SCAN_LIMIT, wide and nocase modes);
//! * `fast_exec`: `yr_re_fast_exec` for hex strings without alternatives (sorted
//!   position list; shortest forward match; exhaustive backward).
//! All state lives in a reusable `Machine` (no allocation per call after warm-up).

use super::emit::{Op, Program};

pub const SCAN_LIMIT: usize = 1024;
pub const MAX_FIBERS: usize = 1024;
const MAX_STACK: usize = 1024;
const NIL: u32 = u32::MAX;

pub const F_WIDE: u32 = 1;
pub const F_NOCASE: u32 = 2;
pub const F_DOTALL: u32 = 4;
pub const F_BACKWARDS: u32 = 8;
pub const F_EXHAUSTIVE: u32 = 16;
pub const F_GREEDY: u32 = 32;

#[inline]
pub fn lower(c: u8) -> u8 {
    c.to_ascii_lowercase()
}

#[inline]
pub fn altercase(c: u8) -> u8 {
    if c.is_ascii_alphabetic() { c ^ 0x20 } else { c }
}

#[inline]
fn is_word(data: &[u8], at: usize, cs: usize) -> bool {
    let c = data[at];
    let r = c.is_ascii_alphanumeric() || c == b'_';
    if cs == 2 { r && data.get(at + 1) == Some(&0) } else { r }
}

#[derive(Clone)]
struct Fiber {
    alive: bool,
    ip: u32,
    rc: i32,
    stack: Vec<u16>,
    prev: u32,
    next: u32,
}

/// Reusable fiber storage.
#[derive(Default)]
pub struct Machine {
    fibers: Vec<Fiber>,
    free: Vec<u32>,
    head: u32,
    tail: u32,
    splits: Vec<Vec<u8>>,
    // fast exec
    pos: Vec<(isize, u32)>,
    pos2: Vec<(isize, u32)>,
    pending: Vec<(isize, u32)>,
}

/// Outcome of an execution.
pub enum ExecError {
    TooManyFibers,
}

impl Machine {
    pub fn new() -> Machine {
        Machine { head: NIL, tail: NIL, ..Default::default() }
    }

    fn alloc(&mut self) -> Result<u32, ExecError> {
        if let Some(i) = self.free.pop() {
            let f = &mut self.fibers[i as usize];
            f.alive = true;
            f.ip = 0;
            f.rc = -1;
            f.stack.clear();
            f.prev = NIL;
            f.next = NIL;
            return Ok(i);
        }
        if self.fibers.len() >= MAX_FIBERS {
            return Err(ExecError::TooManyFibers);
        }
        self.fibers.push(Fiber { alive: true, ip: 0, rc: -1, stack: Vec::new(), prev: NIL, next: NIL });
        Ok((self.fibers.len() - 1) as u32)
    }

    /// Clone `f` and insert the copy right after it.
    fn split(&mut self, f: u32) -> Result<u32, ExecError> {
        let n = self.alloc()?;
        let (ip, rc, next) = {
            let src = &self.fibers[f as usize];
            (src.ip, src.rc, src.next)
        };
        let stack = std::mem::take(&mut self.fibers[n as usize].stack);
        let mut stack = stack;
        stack.clear();
        stack.extend_from_slice(&self.fibers[f as usize].stack);
        {
            let nf = &mut self.fibers[n as usize];
            nf.ip = ip;
            nf.rc = rc;
            nf.stack = stack;
            nf.prev = f;
            nf.next = next;
        }
        if next != NIL {
            self.fibers[next as usize].prev = n;
        }
        self.fibers[f as usize].next = n;
        if self.tail == f {
            self.tail = n;
        }
        Ok(n)
    }

    /// Remove `f`; returns the next fiber.
    fn kill(&mut self, f: u32) -> u32 {
        let (prev, next) = {
            let x = &self.fibers[f as usize];
            (x.prev, x.next)
        };
        if prev != NIL {
            self.fibers[prev as usize].next = next;
        }
        if next != NIL {
            self.fibers[next as usize].prev = prev;
        }
        if self.tail == f {
            self.tail = prev;
        }
        if self.head == f {
            self.head = next;
        }
        self.fibers[f as usize].alive = false;
        self.free.push(f);
        next
    }

    fn kill_tail(&mut self, f: u32) {
        let mut x = f;
        while x != NIL {
            x = self.kill(x);
        }
    }

    fn kill_all(&mut self) {
        let h = self.head;
        if h != NIL {
            self.kill_tail(h);
        }
    }

    fn exists_before(&self, target: u32) -> bool {
        let t = &self.fibers[target as usize];
        let mut x = self.head;
        while x != NIL && x != target {
            let f = &self.fibers[x as usize];
            if f.ip == t.ip && f.rc == t.rc && f.stack == t.stack {
                return true;
            }
            x = f.next;
        }
        false
    }

    fn sync(&mut self, prog: &Program, start: u32, depth: usize) -> Result<(), ExecError> {
        if self.splits.len() <= depth {
            self.splits.resize(depth + 1, Vec::new());
        }
        self.splits[depth].clear();
        let mut fiber = start;
        let last = self.fibers[start as usize].next;
        while fiber != last && fiber != NIL {
            let ip = self.fibers[fiber as usize].ip;
            let Some(op) = prog.ops.get(ip as usize).copied() else {
                fiber = self.kill(fiber);
                continue;
            };
            match op {
                Op::SplitA { id, target } | Op::SplitB { id, target } => {
                    if self.splits[depth].contains(&id) {
                        fiber = self.kill(fiber);
                    } else {
                        let b = self.split(fiber)?;
                        let (mut a, mut bb) = (fiber, b);
                        if matches!(op, Op::SplitB { .. }) {
                            std::mem::swap(&mut a, &mut bb);
                        }
                        self.fibers[a as usize].ip = ip + 1;
                        self.fibers[bb as usize].ip = target;
                        self.splits[depth].push(id);
                    }
                }
                Op::RepeatStart { greedy, min, max: _, end } => {
                    let mut a = fiber;
                    if min == 0 {
                        let mut b = self.split(fiber)?;
                        if !greedy {
                            std::mem::swap(&mut a, &mut b);
                        }
                        self.fibers[b as usize].ip = end;
                    }
                    let fa = &mut self.fibers[a as usize];
                    if fa.stack.len() >= MAX_STACK {
                        fiber = self.kill(a);
                        continue;
                    }
                    fa.stack.push(0);
                    fa.ip = ip + 1;
                }
                Op::RepeatEnd { greedy, min, max, body } => {
                    let cnt = {
                        let f = &mut self.fibers[fiber as usize];
                        match f.stack.last_mut() {
                            Some(t) => {
                                *t = t.wrapping_add(1);
                                *t
                            }
                            None => {
                                // cannot happen with well-formed code
                                u16::MAX
                            }
                        }
                    };
                    if cnt < min {
                        self.fibers[fiber as usize].ip = body;
                        continue;
                    }
                    let mut a = fiber;
                    if cnt < max {
                        let mut b = self.split(fiber)?;
                        if greedy {
                            std::mem::swap(&mut a, &mut b);
                        }
                        self.fibers[b as usize].ip = body;
                    }
                    let fa = &mut self.fibers[a as usize];
                    fa.stack.pop();
                    fa.ip = ip + 1;
                }
                Op::RepeatAny { greedy, min, max } => {
                    let rc = {
                        let f = &mut self.fibers[fiber as usize];
                        if f.rc == -1 {
                            f.rc = 0;
                        }
                        f.rc
                    };
                    if rc < min as i32 {
                        self.fibers[fiber as usize].rc += 1;
                        fiber = self.fibers[fiber as usize].next;
                    } else if rc < max as i32 {
                        let next = self.fibers[fiber as usize].next;
                        let mut a = fiber;
                        let mut b = self.split(fiber)?;
                        if !greedy {
                            std::mem::swap(&mut a, &mut b);
                        }
                        self.fibers[a as usize].rc += 1;
                        self.fibers[b as usize].ip = ip + 1;
                        self.fibers[b as usize].rc = -1;
                        self.sync(prog, b, depth + 1)?;
                        fiber = next;
                    } else {
                        let f = &mut self.fibers[fiber as usize];
                        f.ip = ip + 1;
                        f.rc = -1;
                    }
                }
                Op::Jump(t) => self.fibers[fiber as usize].ip = t,
                _ => fiber = self.fibers[fiber as usize].next,
            }
        }
        Ok(())
    }

    /// `yr_re_exec`. `pos` is the input position; forward size = data.len() - pos,
    /// backward size = pos. Returns the forward match length (-1 = none) for
    /// non-exhaustive runs; exhaustive runs call `cb(match_start, len)`.
    pub fn exec(
        &mut self,
        prog: &Program,
        start_ip: u32,
        data: &[u8],
        pos: usize,
        flags: u32,
        cb: &mut dyn FnMut(usize, usize),
    ) -> Result<i64, ExecError> {
        let r = self.exec_inner(prog, start_ip, data, pos, flags, cb);
        self.kill_all();
        r
    }

    fn exec_inner(
        &mut self,
        prog: &Program,
        start_ip: u32,
        data: &[u8],
        pos: usize,
        flags: u32,
        cb: &mut dyn FnMut(usize, usize),
    ) -> Result<i64, ExecError> {
        let cs: usize = if flags & F_WIDE != 0 { 2 } else { 1 };
        let backwards = flags & F_BACKWARDS != 0;
        let fwd_size = data.len().saturating_sub(pos);
        let bwd_size = pos.min(data.len());
        let mut max_bytes = if backwards { bwd_size.min(SCAN_LIMIT) } else { fwd_size.min(SCAN_LIMIT) };
        max_bytes -= max_bytes % cs;
        // input as a signed position
        let mut input: isize = if backwards { pos as isize - cs as isize } else { pos as isize };
        let incr: isize = if backwards { -(cs as isize) } else { cs as isize };
        let mut bytes_matched: usize = 0;
        let mut matches: i64 = -1;
        let nocase = flags & F_NOCASE != 0;
        let dotall = flags & F_DOTALL != 0;
        let exhaustive = flags & F_EXHAUSTIVE != 0;

        self.head = NIL;
        self.tail = NIL;
        let f = self.alloc()?;
        self.fibers[f as usize].ip = start_ip;
        self.head = f;
        self.tail = f;
        self.sync(prog, f, 0)?;

        let data_end = data.len() as isize;
        while self.head != NIL {
            // dedupe
            let mut x = self.head;
            while x != NIL {
                let next = self.fibers[x as usize].next;
                if self.exists_before(x) {
                    self.kill(x);
                }
                x = next;
            }
            let mut fiber = self.head;
            while fiber != NIL {
                let ip = self.fibers[fiber as usize].ip;
                let Some(op) = prog.ops.get(ip as usize).copied() else {
                    fiber = self.kill(fiber);
                    continue;
                };
                // prolog for consuming instructions
                let consuming = !matches!(
                    op,
                    Op::WordBoundary | Op::NonWordBoundary | Op::MatchAtStart | Op::MatchAtEnd | Op::Match
                );
                let ok_input = !(bytes_matched >= max_bytes
                    || input < 0
                    || input >= data_end
                    || (cs == 2 && data.get(input as usize + 1) != Some(&0)));
                enum Act {
                    None,
                    Kill,
                    KillTail,
                    Continue,
                }
                let act: Act;
                if consuming && !ok_input {
                    act = Act::Kill;
                } else {
                    let c = if consuming { data[input as usize] } else { 0 };
                    match op {
                        Op::Any => {
                            let m = dotall || c != b'\n';
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if m { Act::None } else { Act::Kill };
                        }
                        Op::RepeatAny { .. } => {
                            let m = dotall || c != b'\n';
                            act = if m { Act::None } else { Act::Kill };
                        }
                        Op::Literal(v) => {
                            let m = if nocase { lower(c) == lower(v) } else { c == v };
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if m { Act::None } else { Act::Kill };
                        }
                        Op::NotLiteral(v) => {
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if c != v { Act::None } else { Act::Kill };
                        }
                        Op::MaskedLiteral(v, m) => {
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if c & m == v { Act::None } else { Act::Kill };
                        }
                        Op::MaskedNotLiteral(v, m) => {
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if c & m != v { Act::None } else { Act::Kill };
                        }
                        Op::Class(idx) => {
                            let m = match prog.classes.get(idx as usize) {
                                Some(cl) => {
                                    let mut r = cl.has(c);
                                    if nocase {
                                        r |= cl.has(altercase(c));
                                    }
                                    if cl.negated { !r } else { r }
                                }
                                None => false,
                            };
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if m { Act::None } else { Act::Kill };
                        }
                        Op::WordChar | Op::NonWordChar => {
                            let w = is_word(data, input as usize, cs);
                            let m = if matches!(op, Op::WordChar) { w } else { !w };
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if m { Act::None } else { Act::Kill };
                        }
                        Op::Space | Op::NonSpace => {
                            let s = matches!(c, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c);
                            let m = if matches!(op, Op::Space) { s } else { !s };
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if m { Act::None } else { Act::Kill };
                        }
                        Op::Digit | Op::NonDigit => {
                            let d = c.is_ascii_digit();
                            let m = if matches!(op, Op::Digit) { d } else { !d };
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if m { Act::None } else { Act::Kill };
                        }
                        Op::WordBoundary | Op::NonWordBoundary => {
                            let prev_pos = input - incr;
                            let prev = prev_pos + cs as isize <= data_end && prev_pos >= 0 && is_word(data, prev_pos as usize, cs);
                            let this = input + cs as isize <= data_end && input >= 0 && is_word(data, input as usize, cs);
                            let mut m = prev != this;
                            if matches!(op, Op::NonWordBoundary) {
                                m = !m;
                            }
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if m { Act::Continue } else { Act::Kill };
                        }
                        Op::MatchAtStart => {
                            let kill = if backwards { bwd_size > bytes_matched } else { bwd_size > 0 || bytes_matched != 0 };
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if kill { Act::Kill } else { Act::Continue };
                        }
                        Op::MatchAtEnd => {
                            let kill = backwards || fwd_size > bytes_matched;
                            self.fibers[fiber as usize].ip = ip + 1;
                            act = if kill { Act::Kill } else { Act::Continue };
                        }
                        Op::Match => {
                            matches = bytes_matched as i64;
                            if exhaustive {
                                let start = if backwards { (input + cs as isize).max(0) as usize } else { pos };
                                cb(start, bytes_matched);
                                act = Act::Kill;
                            } else {
                                act = Act::KillTail;
                            }
                        }
                        _ => {
                            // epsilon ops never reach here after sync
                            act = Act::Kill;
                        }
                    }
                }
                match act {
                    Act::Kill => fiber = self.kill(fiber),
                    Act::KillTail => {
                        self.kill_tail(fiber);
                        fiber = NIL;
                    }
                    Act::Continue => {
                        self.sync(prog, fiber, 0)?;
                        if !self.fibers[fiber as usize].alive {
                            // libyara would keep using a recycled fiber here (undefined
                            // behaviour); end this step instead.
                            fiber = NIL;
                        }
                    }
                    Act::None => {
                        let next = self.fibers[fiber as usize].next;
                        self.sync(prog, fiber, 0)?;
                        fiber = next;
                    }
                }
            }
            input += incr;
            bytes_matched += cs;
        }
        Ok(matches)
    }

    /// `yr_re_fast_exec` (hex strings without alternatives).
    pub fn fast_exec(
        &mut self,
        prog: &Program,
        start_ip: u32,
        data: &[u8],
        pos: usize,
        flags: u32,
        cb: &mut dyn FnMut(usize, usize),
    ) -> i64 {
        let backwards = flags & F_BACKWARDS != 0;
        let exhaustive = flags & F_EXHAUSTIVE != 0;
        let incr: isize = if backwards { -1 } else { 1 };
        let fwd_size = data.len().saturating_sub(pos);
        let bwd_size = pos.min(data.len());
        let max_bytes = if backwards { bwd_size.min(SCAN_LIMIT) } else { fwd_size.min(SCAN_LIMIT) } as isize;
        let input_data = pos as isize;
        // positions: (input, round), kept sorted by input pointer (for backwards the
        // C code compares pointers too, so larger = closer to input_data).
        self.pos.clear();
        self.pos.push((if backwards { input_data - 1 } else { input_data }, 0));
        let mut round: u32 = 0;
        let mut ip = start_ip as usize;
        loop {
            if self.pos.is_empty() {
                return -1;
            }
            let Some(op) = prog.ops.get(ip).copied() else { return -1 };
            let mut out = std::mem::take(&mut self.pos2);
            out.clear();
            let list = std::mem::take(&mut self.pos);
            let mut i = 0usize;
            // Newly created positions for round+1 are inserted in sorted order; we
            // model the linked list with a vector rebuilt per round.
            let mut pending = std::mem::take(&mut self.pending);
            pending.clear();
            while i < list.len() {
                let (inp, r) = list[i];
                i += 1;
                if r != round {
                    // position created for a later round (kept)
                    out.push((inp, r));
                    continue;
                }
                let bytes_matched = if backwards { input_data - inp - 1 } else { inp - input_data };
                let rd = |p: isize| -> Option<u8> { if p >= 0 { data.get(p as usize).copied() } else { None } };
                let mut matched = false;
                let mut newinp = inp;
                match op {
                    Op::Any => {
                        if bytes_matched < max_bytes {
                            matched = true;
                            newinp = inp + incr;
                        }
                    }
                    Op::Literal(v) => {
                        if bytes_matched < max_bytes && rd(inp) == Some(v) {
                            matched = true;
                            newinp = inp + incr;
                        }
                    }
                    Op::NotLiteral(v) => {
                        if bytes_matched < max_bytes && rd(inp).is_some_and(|c| c != v) {
                            matched = true;
                            newinp = inp + incr;
                        }
                    }
                    Op::MaskedLiteral(v, m) => {
                        if bytes_matched < max_bytes && rd(inp).is_some_and(|c| c & m == v) {
                            matched = true;
                            newinp = inp + incr;
                        }
                    }
                    Op::MaskedNotLiteral(v, m) => {
                        if bytes_matched < max_bytes && rd(inp).is_some_and(|c| c & m != v) {
                            matched = true;
                            newinp = inp + incr;
                        }
                    }
                    Op::RepeatAny { min, max, .. } => {
                        if bytes_matched + (min as isize) < max_bytes {
                            matched = true;
                            let next_op = prog.ops.get(ip + 1).copied();
                            for j in (min as isize + 1)..=(max as isize) {
                                if bytes_matched + j >= max_bytes {
                                    break;
                                }
                                let next_input = inp + j * incr;
                                if let Some(Op::Literal(v)) = next_op {
                                    if rd(next_input) != Some(v) {
                                        continue;
                                    }
                                }
                                pending.push((next_input, round + 1));
                            }
                            newinp = inp + (min as isize) * incr;
                        }
                    }
                    Op::Match => {
                        if exhaustive {
                            let start = if backwards { (inp + 1).max(input_data - bwd_size as isize) } else { input_data };
                            let len = bytes_matched.min(max_bytes).max(0) as usize;
                            cb(start.max(0) as usize, len);
                        } else {
                            self.pos = list;
                            self.pos2 = out;
                            return bytes_matched as i64;
                        }
                    }
                    _ => {}
                }
                if matched {
                    out.push((newinp, round + 1));
                }
            }
            // Merge pending positions (dedupe positions already present for round+1).
            if !pending.is_empty() {
                for &p in pending.iter() {
                    if !out.iter().any(|q| q.0 == p.0 && q.1 == p.1) {
                        out.push(p);
                    }
                }
            }
            self.pending = pending;
            // Keep the list sorted by pointer value (stable for equal inputs).
            out.sort_by(|a, b| a.0.cmp(&b.0));
            // For Match in exhaustive mode all positions were consumed.
            if matches!(op, Op::Match) {
                return -1;
            }
            self.pos = out;
            self.pos2 = list;
            round += 1;
            ip += 1;
            // Skip over the op arguments: ops are one slot each in our encoding.
        }
    }
}
