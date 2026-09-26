//! `--filters` handling, a port of volatility3 `cli/text_filter.py` (derived from Volatility 3,
//! Volatility Software License 1.0).
//!
//! A filter is `[+-]columnname,pattern[!]`: `-` excludes, a trailing `!` makes the pattern a
//! regular expression, the column is found by case-insensitive substring match on the column
//! names (none given or none found: any column). A row is kept when ANY filter matches.

use super::regex::Regex;
use crate::renderers::Column;

struct ColumnFilter {
    column: Option<usize>,
    pattern: String,
    regex: Option<Result<Regex, String>>,
    exclude: bool,
}

/// Why a filter could not be evaluated: python raises (IndexError / re.error) and the CLI dies
/// with a traceback.
#[derive(Debug, Clone)]
pub struct FilterCrash(pub String);

pub struct CliFilter {
    filters: Vec<ColumnFilter>,
}

impl CliFilter {
    /// `CLIFilter._prepare`
    pub fn new(columns: &[Column], filters: &[String]) -> CliFilter {
        let mut out = Vec::new();
        for f in filters {
            let mut f = f.as_str();
            let mut exclude = false;
            if let Some(r) = f.strip_prefix('-') {
                exclude = true;
                f = r;
            } else if let Some(r) = f.strip_prefix('+') {
                f = r;
            }
            let (column_name, mut pattern) = match f.split_once(',') {
                None => (None, f.to_string()),
                Some((c, rest)) => (Some(c), rest.to_string()),
            };
            let mut regex = false;
            if pattern.ends_with('!') {
                regex = true;
                pattern.pop();
            }
            let mut column = None;
            if let Some(name) = column_name.filter(|n| !n.is_empty()) {
                let lname = name.to_lowercase();
                column = columns.iter().position(|c| c.name.to_lowercase().contains(&lname));
            }
            if !pattern.is_empty() {
                let re = if regex { Some(Regex::new(&pattern).map_err(|e| e.0)) } else { None };
                out.push(ColumnFilter { column, pattern, regex: re, exclude });
            }
        }
        CliFilter { filters: out }
    }

    pub fn is_active(&self) -> bool {
        !self.filters.is_empty()
    }

    /// `CLIFilter.filter`: true when the row must be dropped. `row` holds python's `f"{item}"`
    /// of each value the renderer passes in.
    pub fn filter<S: AsRef<str>>(&self, row: &[S]) -> Result<bool, FilterCrash> {
        if self.filters.is_empty() {
            return Ok(false);
        }
        for f in &self.filters {
            let found = match f.column {
                None => {
                    let mut any = false;
                    for item in row {
                        if f.find(item.as_ref())? {
                            any = true;
                            break;
                        }
                    }
                    any
                }
                Some(c) => match row.get(c) {
                    Some(item) => f.find(item.as_ref())?,
                    None => return Err(FilterCrash("IndexError: list index out of range".into())),
                },
            };
            if found != f.exclude {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl ColumnFilter {
    fn find(&self, item: &str) -> Result<bool, FilterCrash> {
        match &self.regex {
            None => Ok(item.contains(self.pattern.as_str())),
            Some(Ok(re)) => Ok(re.is_match(item)),
            Some(Err(e)) => Err(FilterCrash(format!("re.PatternError: {e}"))),
        }
    }
}
