//! Lazy DFA (stub).
use super::hir::Hir;
pub struct Searcher;
pub struct Cache;
impl Searcher {
    pub fn new(_h: &Hir) -> Option<Searcher> {
        None
    }
    pub fn new_cache(&self) -> Cache {
        Cache
    }
    pub fn strategy_name(&self) -> &'static str {
        "dfa"
    }
    pub fn find(&self, _c: &mut Cache, _hay: &[u8], _start: usize, _anchored: bool, _must_advance: bool) -> Option<(usize, usize)> {
        None
    }
}
