//! Rule front-end tests: compile errors (checked against yara-python 4.5.4
//! messages) and condition evaluation with hand-made match lists.

use super::*;
use crate::yara::scan::Match;

fn m(offset: usize, len: usize) -> Match {
    Match { offset, len, xor_key: 0 }
}

fn err(src: &str) -> String {
    match Rules::compile(src) {
        Ok(_) => "OK".into(),
        Err(e) => e.to_string(),
    }
}

/// Names of matching rules for `src` given per-string matches.
fn names(src: &str, data: &[u8], matches: &[Vec<Match>]) -> Vec<String> {
    let r = Rules::compile(src).unwrap_or_else(|e| panic!("compile failed: {e}"));
    r.evaluate(data, matches).into_iter().map(|m| m.rule).collect()
}

fn t(cond: &str) -> bool {
    let src = format!("rule a {{ condition: {cond} }}");
    !names(&src, b"hello", &[]).is_empty()
}

#[test]
fn yara_rules_basic_conditions() {
    assert!(t("true"));
    assert!(!t("false"));
    assert!(t("1"));
    assert!(!t("0"));
    assert!(t("1.5"));
    assert!(!t("0.0"));
    assert!(t("\"x\""));
    assert!(!t("\"\""));
    assert!(t("/abc/"));
    assert!(t("filesize == 5"));
    assert!(t("uint8(0) == 0x68"));
    assert!(t("uint16be(0) == 0x6865"));
    assert!(t("uint32(0) == 0x6c6c6568"));
    assert!(t("int8(0) == 104"));
    assert!(!t("uint32(2) == 0"));
    assert!(t("not defined uint32(2)"));
    assert!(!t("not uint32(2) == 0"));
    assert!(t("not defined entrypoint"));
    assert!(t("1 + 2 * 3 == 7"));
    assert!(t("(1 + 2) * 3 == 9"));
    assert!(t("7 \\ 2 == 3"));
    assert!(t("-7 \\ 2 == -3"));
    assert!(t("-7 % 3 == -1"));
    assert!(t("1 << 3 == 8"));
    assert!(t("-16 >> 2 == -4"));
    assert!(t("~0 == -1"));
    assert!(t("6 & 3 == 2"));
    assert!(t("6 | 3 == 7"));
    assert!(t("6 ^ 3 == 5"));
    assert!(t("1 == 1.0"));
    assert!(t("1.5 > 1"));
    assert!(t("2 >= 1.5 and 1 < 1.5"));
    assert!(t("\"abc\" == \"abc\""));
    assert!(t("\"abc\" < \"abd\""));
    assert!(t("\"\\x80\" < \"a\""));
    assert!(t("\"abc\" contains \"b\""));
    assert!(t("\"abc\" icontains \"B\""));
    assert!(t("\"abc\" startswith \"ab\""));
    assert!(t("\"abc\" istartswith \"AB\""));
    assert!(t("\"abc\" endswith \"bc\""));
    assert!(t("\"abc\" iendswith \"BC\""));
    assert!(t("\"abc\" iequals \"ABC\""));
    assert!(!t("\"abc\" iequals \"AB\""));
    assert!(t("\"abc\" matches /b/"));
    assert!(!t("\"abc\" matches /$/"));
    assert!(t("\"ABC\" matches /b/i"));
    assert!(!t("-0x5452505452501 == 0"));
    assert!(!t("not (-0x5452505452501 == 0)"));
    assert!(t("not (uint8(100) == 1 and true)"));
    assert!(t("uint8(100) == 1 or true"));
    assert!(!t("uint8(100) == 1 and true"));
    assert!(t("1 \\ (1 - 1 + filesize - filesize) == 0 or true"));
    assert!(!t("defined (1 \\ (filesize - filesize))"));
    assert!(t("defined (1 % (filesize - 4))"));
    assert!(t("0x7fffffffffffffff + filesize < 0"));
}

#[test]
fn yara_rules_string_conditions() {
    let src = r#"rule a { strings: $a = "x" $b = "y" $c = "z" condition: $a and #a == 2 and @a[2] == 10 and !a == 1 and @a == 5 and not $b and #c == 0 }"#;
    let ms = vec![vec![m(5, 1), m(10, 1)], vec![], vec![]];
    assert_eq!(names(src, b"", &ms), vec!["a"]);
    let ms1 = vec![vec![m(5, 1)], vec![], vec![]];
    let src2 = r#"rule a { strings: $a = "x" $b = "y" $c = "z" condition: ($a or $b or $c) and not defined @a[2] }"#;
    assert_eq!(names(src2, b"", &ms1), vec!["a"]);
    let at = r#"rule a { strings: $a = "x" condition: $a at 5 } rule b { strings: $a = "x" condition: $a at 6 }"#;
    assert_eq!(names(at, b"", &[vec![m(5, 1)], vec![m(5, 1)]]), vec!["a"]);
    let inr = r#"rule a { strings: $a = "x" condition: $a in (0..5) and #a in (5..10) == 2 }"#;
    assert_eq!(names(inr, b"", &[vec![m(5, 1), m(10, 1), m(11, 1)]]), vec!["a"]);
    let of = r#"
        rule any1 { strings: $a1 = "a" $a2 = "b" $b = "c" condition: (any of ($a*)) and ($a1 or $a2 or $b or true) }
        rule all1 { strings: $a1 = "a" $a2 = "b" $b = "c" condition: (all of them) and ($a1 or $a2 or $b or true) }
        rule none1 { strings: $a1 = "a" $a2 = "b" $b = "c" condition: (none of ($a1, $b)) and ($a1 or $a2 or $b or true) }
        rule two { strings: $a1 = "a" $a2 = "b" $b = "c" condition: (2 of them) and ($a1 or $a2 or $b or true) }
        rule pct { strings: $a1 = "a" $a2 = "b" $b = "c" condition: (60% of them) and ($a1 or $a2 or $b or true) }
        rule pct2 { strings: $a1 = "a" $a2 = "b" $b = "c" condition: (50% of them) and ($a1 or $a2 or $b or true) }
        rule ofin { strings: $a1 = "a" $a2 = "b" $b = "c" condition: (all of ($a*) in (0..20)) and ($a1 or $a2 or $b or true) }
        rule ofat { strings: $a1 = "a" $a2 = "b" $b = "c" condition: (any of them at 3) and ($a1 or $a2 or $b or true) }
    "#;
    // strings: any1 (0..3) all1 (3..6) none1 (6..9) two (9..12) pct (12..15) pct2 (15..18) ofin (18..21) ofat(21..24)
    let mut ms = vec![Vec::new(); 24];
    for base in (0..24).step_by(3) {
        ms[base] = vec![m(3, 1)];
        ms[base + 1] = vec![m(15, 1)];
    }
    assert_eq!(names(of, b"", &ms), vec!["any1", "two", "pct", "pct2", "ofin", "ofat"]);
}

#[test]
fn yara_rules_loops() {
    let src = r#"rule a { strings: $a = "x" condition: for all i in (1..#a) : (@a[i] < 100) }
                 rule b { strings: $a = "x" condition: for any i in (1..#a) : (@a[i] > 100) }
                 rule c { condition: for any i in (1, 2, 3) : (i == 2) }
                 rule d { condition: for all i in (1, 2, 3) : (i < 3) }
                 rule e { condition: for none i in (1..3) : (i == 5) }
                 rule f { strings: $a = "x" $b = "y" condition: for any of ($a, $b) : ($ at 10) }
                 rule g { strings: $a = "x" $b = "y" condition: for all of ($a, $b) : (# >= 1 and @ > 5 and ! == 1) }
                 rule h { condition: for 2 s in ("a", "bb", "ccc") : (s contains "c" or s == "a") }
                 rule i { condition: for any i in (1..3) : (for any j in (i..3) : (i * j == 9)) }
                 rule j { condition: for 3 i in (1..1) : (5) }
                 rule k { strings: $a = "x" condition: for all i in (1..#a) : (true) }
                 rule l { condition: for any i in (5..filesize) : (true) }"#;
    let ms = vec![
        vec![m(10, 1), m(20, 1)],
        vec![m(10, 1), m(20, 1)],
        vec![m(10, 1)],
        vec![m(30, 1)],
        vec![m(10, 1)],
        vec![m(6, 1)],
        vec![],
    ];
    assert_eq!(names(src, b"", &ms), vec!["a", "c", "e", "f", "g", "h", "i", "j"]);
}

#[test]
fn yara_rules_references_private_global() {
    let src = r#"
        private rule p { condition: true }
        rule a { condition: p }
        rule c { condition: false }
        rule b { condition: a and not c }
        rule d { condition: any of (a, b*) }
        rule e { condition: all of (a, b, c) }
        rule f { condition: 2 of (a, b, c) }
        rule g { condition: 50% of (a*, c) }
    "#;
    assert_eq!(names(src, b"", &[]), vec!["a", "b", "d", "f", "g"]);

    let g = Rules::compile_namespaced(&[
        ("x", "global rule gx { condition: filesize > 10 } rule a { condition: true }"),
        ("y", "rule b { condition: true } private global rule gy { condition: true }"),
    ])
    .unwrap();
    let r: Vec<String> = g.evaluate(b"short", &[]).into_iter().map(|m| format!("{}:{}", m.namespace, m.rule)).collect();
    assert_eq!(r, vec!["y:b"]);
    let r: Vec<String> = g.evaluate(b"long enough data", &[]).into_iter().map(|m| format!("{}:{}", m.namespace, m.rule)).collect();
    assert_eq!(r, vec!["x:gx", "x:a", "y:b"]);
}

#[test]
fn yara_rules_result_shape() {
    let src = r#"rule r : t1 t2 { meta: s = "v\x00w" i = 4294967295 n = -3 b = true s = 7
        strings: $a = "ab" $p = "cd" private $n = "zz" condition: any of them }"#;
    let r = Rules::compile(src).unwrap();
    let data = b"xxabcdxx";
    let ms = vec![vec![m(2, 2)], vec![m(4, 2)], vec![]];
    let out = r.evaluate(data, &ms);
    assert_eq!(out.len(), 1);
    let x = &out[0];
    assert_eq!(x.namespace, "default");
    assert_eq!(x.tags, vec!["t1", "t2"]);
    assert_eq!(x.meta, vec![
        ("s".to_string(), MetaValue::Int(7)),
        ("i".to_string(), MetaValue::Int(-1)),
        ("n".to_string(), MetaValue::Int(-3)),
        ("b".to_string(), MetaValue::Bool(true))
    ]);
    assert_eq!(x.strings.len(), 2);
    assert_eq!(x.strings[0].identifier, "$a");
    assert_eq!(x.strings[0].instances, vec![Instance { offset: 2, matched_data: b"ab".to_vec(), matched_length: 2, xor_key: 0 }]);
    assert_eq!(x.strings[1].identifier, "$p");
    assert!(x.strings[1].instances.is_empty());
    // Long match: data truncated to 512 bytes.
    let r = Rules::compile(r#"rule r { strings: $a = "a" condition: $a }"#).unwrap();
    let data = vec![b'a'; 1000];
    let out = r.evaluate(&data, &[vec![m(0, 700)]]);
    assert_eq!(out[0].strings[0].instances[0].matched_data.len(), 512);
    assert_eq!(out[0].strings[0].instances[0].matched_length, 700);
    // Out of range matches never panic.
    let out = r.evaluate(b"ab", &[vec![m(5, 10)]]);
    assert!(out[0].strings[0].instances[0].matched_data.is_empty());
}

#[test]
fn yara_rules_fixed_offset() {
    let fixed = |src: &str| -> Vec<Option<i64>> {
        Rules::compile(src).unwrap().string_defs().iter().map(|d| d.fixed_offset).collect()
    };
    assert_eq!(fixed(r#"rule a { strings: $a = "MZ" condition: $a at 0 }"#), vec![Some(0)]);
    assert_eq!(fixed(r#"rule a { strings: $a = "MZ" condition: $a at 0 and $a at 0 }"#), vec![Some(0)]);
    assert_eq!(fixed(r#"rule a { strings: $a = "MZ" condition: $a at 0 or $a at 2 }"#), vec![None]);
    assert_eq!(fixed(r#"rule a { strings: $a = "MZ" condition: $a at filesize }"#), vec![None]);
    assert_eq!(fixed(r#"rule a { strings: $a = "MZ" condition: $a at 0 and #a == 1 }"#), vec![None]);
    assert_eq!(fixed(r#"rule a { strings: $a = "MZ" condition: $a at 0 and any of them }"#), vec![None]);
    assert_eq!(fixed(r#"rule a { strings: $a = "MZ" condition: $a }"#), vec![None]);
    assert_eq!(fixed(r#"rule a { strings: $_a = "MZ" condition: true }"#), vec![None]);
    assert_eq!(fixed(r#"rule a { strings: $a = "MZ" condition: $a at (2 + 3) }"#), vec![Some(5)]);
    assert_eq!(
        fixed(r#"rule a { strings: $a = "A" $b = "B" condition: for any of ($b) : ($ at 7) and $a at 7 }"#),
        vec![Some(7), None]
    );
    assert_eq!(
        fixed(r#"rule a { strings: $a = "A" $b = "B" condition: $a at 3 and for any of ($b) : ($ at 7) }"#),
        vec![None, None]
    );
    assert_eq!(fixed(r#"rule a { strings: $a = "A" base64 condition: $a at 3 }"#), vec![None]);
}

#[test]
fn yara_rules_compile_errors_match_yara_python() {
    let cases: &[(&str, &str)] = &[
        ("rule a { condition: true == true }", "line 1: syntax error, unexpected ==, expecting '}'"),
        ("rule a { condition: 1 < 2 < 3 }", "line 1: syntax error, unexpected <, expecting '}'"),
        ("rule a { condition: (1) + 1 == 2 }", "OK"),
        ("rule a { strings: $a=\"x\" condition: 1+49% of them }", "line 1: syntax error, unexpected <of>"),
        ("rule a { strings: $a=\"x\" condition: 2*50% of them }", "OK"),
        ("rule a { strings: $a=\"x\" condition: -50% of them }", "line 1: percentage must be between 1 and 100 (inclusive)"),
        ("rule a { condition: foo } rule b { condition: bar }", "line 1: undefined identifier \"bar\""),
        ("rule a { strings: $a = \"abc\ndef\" condition: $a }", "line 2: syntax error, unexpected end of file, expecting text string"),
        ("rule a { strings: $a = \"abc\\q\" condition: $a }", "line 1: syntax error, unexpected end of file, expecting text string"),
        ("rule a { strings: $a = \"\" condition: $a }", "line 1: empty string \"$a\""),
        ("rule a { strings: $a = \"x\" $a = \"y\" condition: $a }", "line 1: duplicated string identifier \"$a\""),
        ("rule a { strings: $a = \"x\" condition: true }", "line 1: unreferenced string \"$a\""),
        ("rule a { strings: $_a = \"x\" condition: true }", "OK"),
        ("rule a { strings: $ = \"x\" condition: true }", "line 1: unreferenced string \"$\""),
        ("rule a { strings: $ = \"x\" condition: $ }", "line 1: wrong use of anonymous string"),
        ("rule a { strings: $a = \"x\" xor nocase condition: $a }", "line 1: invalid modifier combination: xor nocase"),
        ("rule a { strings: $a = \"x\" base64 nocase condition: $a }", "line 1: invalid modifier combination: base64 nocase"),
        ("rule a { strings: $a = \"x\" base64wide fullword condition: $a }", "line 1: invalid modifier combination: base64wide fullword"),
        ("rule a { strings: $a = \"x\" base64 xor condition: $a }", "line 1: invalid modifier combination: base64 xor"),
        ("rule a { strings: $a = \"x\" xor(256) condition: $a }", "line 1: invalid xor range"),
        ("rule a { strings: $a = \"x\" xor(3-2) condition: $a }", "line 1: xor lower bound exceeds upper bound"),
        ("rule a { strings: $a = \"x\" xor(-1-2) condition: $a }", "line 1: syntax error, unexpected '-', expecting integer number"),
        ("rule a { strings: $a = \"x\" xor(1-256) condition: $a }", "line 1: upper bound for xor range exceeded (max: 255)"),
        ("rule a { strings: $a = \"x\" base64(\"abc\") condition: $a }", "line 1: length of base64 alphabet must be 64"),
        ("rule a { strings: $a = \"x\" wide wide condition: $a }", "line 1: duplicated modifier"),
        (
            "rule a { strings: $a = \"x\" base64 base64wide(\"0123456789012345678901234567890123456789012345678901234567890123\") condition: $a }",
            "line 1: can not specify multiple alphabets",
        ),
        ("rule a { strings: $a = /abc/ xor condition: $a }", "line 1: syntax error, unexpected <xor>, expecting <condition>"),
        ("rule a { strings: $a = { 41 } nocase condition: $a }", "line 1: syntax error, unexpected <nocase>, expecting <condition>"),
        ("rule a { condition: 1 % 0 }", "line 1: division by zero"),
        ("rule a { condition: 1 \\ 0 }", "line 1: division by zero"),
        ("rule a { condition: 1 << -1 }", "line 1: "),
        ("rule a { condition: 9223372036854775807 + 1 }", "line 1: integer overflow in \"9223372036854775807 + 1\""),
        ("rule a { condition: 9223372036854775808 }", "line 1: syntax error, unexpected end of file"),
        ("rule a { condition: 0x8000000000000000 }", "line 1: syntax error, unexpected end of file"),
        ("rule a { condition: 9007199254740992KB }", "line 1: syntax error, unexpected end of file"),
        ("rule a { condition: \"a\" + \"b\" }", "line 1: strings don't support \"+\" operation"),
        ("rule a { condition: \"a\" < 1 }", "line 1: type mismatch"),
        ("rule a { condition: -\"a\" }", "line 1: wrong type \"string\" for - operator"),
        ("rule a { condition: 1.5 % 2 }", "line 1: wrong type \"float\" for % operator"),
        (
            "rule a { strings: $a=\"x\" condition: $a in (5..1) }",
            "line 1: invalid value in condition: \"range lower bound must be less than upper bound\"",
        ),
        (
            "rule a { strings: $a=\"x\" condition: $a in (-1..1) }",
            "line 1: invalid value in condition: \"range lower bound can not be negative\"",
        ),
        ("rule a { strings: $a=\"x\" condition: -1 of them }", "line 1: invalid value in condition: \"-1\""),
        ("rule a { strings: $a=\"x\" condition: \"x\" of them }", "line 1: invalid value in condition: \"x\""),
        ("rule a { strings: $a=\"x\" condition: 0% of them }", "line 1: percentage must be between 1 and 100 (inclusive)"),
        (
            "rule a { condition: for any i in (1..3) : (for any i in (1..2) : (true)) }",
            "line 1: duplicated loop identifier \"i\"",
        ),
        (
            "rule a { condition: for any i in (1..3) : (for any j in (1..2) : (for any k in (1..2) : (for any l in (1..2) : (for any m in (1..2) : (true))))) }",
            "line 1: loop nesting limit exceeded",
        ),
        (
            "rule a { strings: $a=\"x\" condition: for any of them : (for any of them : ($)) }",
            "line 1: 'for <quantifier> of <string set>' loops can't be nested",
        ),
        ("rule a { strings: $a=\"x\" condition: $ }", "line 1: wrong use of anonymous string"),
        ("rule a { condition: b }", "line 1: undefined identifier \"b\""),
        ("rule a { condition: true } rule a { condition: true }", "line 1: duplicated identifier \"a\""),
        ("rule a : x x { condition: true }", "line 1: duplicated tag identifier \"x\""),
        ("rule a { condition: any of (b*) }", "line 1: undefined identifier \"b\""),
        (
            "rule ab { condition: true } rule c { condition: any of (a*) } rule ax { condition: true }",
            "line 1: rule identifier \"ax\" matches previously used wildcard rule set",
        ),
        ("rule a { condition: \"abc\" matches /a{2,1}/ }", "line 1: bad repeat interval"),
        ("rule a { condition: \"abc\" matches /a{99999}/ }", "line 1: repeat interval too large"),
        ("rule a { condition: \"abc\" matches /(a/ }", "line 1: syntax error"),
        ("rule a { condition: \"abc\" matches /[a/ }", "line 1: missing terminating ] for character class"),
        ("rule a { condition: \"abc\" matches /\\1/ }", "line 1: backreferences are not allowed"),
        ("rule a { condition: \"abc\" matches /a**/ }", "line 1: syntax error"),
        ("rule a { condition: \"abc\" matches // }", "line 0: syntax error, unexpected end of file, expecting regular expression"),
        ("rule a { condition: é }", "line 1: syntax error, unexpected end of file"),
        ("rule a { condition: true }\x01", "line 1: non-ascii character"),
        ("rule a { condition: 1 == 1.0 }", "OK"),
        ("rule a { condition: for any i in (\"a\", 1) : (true) }", "line 1: enumerations must be all the same type"),
        (
            "rule a { condition: for any i, j in (1..2) : (true) }",
            "line 1: iterator yields one value on each iteration , but the loop expects 2",
        ),
        ("rule a { condition: for any i in (1..2) : (true) and i }", "line 1: undefined identifier \"i\""),
        ("rule a { condition: 1 >> -1 }", "line 1: "),
        ("rule a { condition: true", "line 0: syntax error, unexpected end of file, expecting '}'"),
        ("rule a {\n condition:\n true\n\n", "line 0: syntax error, unexpected end of file, expecting '}'"),
        ("rule a {\n condition:\n true\n\n}\nrule b {\n strings: $a = \"x\"\n condition: true\n}\n", "line 9: unreferenced string \"$a\""),
        ("rule a {\n strings:\n $a = \"x\"\n $b = \"y\"\n condition:\n $a\n}\n", "line 7: unreferenced string \"$b\""),
        ("rule a {\n strings:\n $a = \"x\"\n $a = \"y\"\n condition:\n $a\n}\n", "line 4: duplicated string identifier \"$a\""),
        ("rule a {\n condition:\n foo and\n bar\n}\n", "line 3: undefined identifier \"foo\""),
        ("rule a {\n condition:\n true == \n true\n}\n", "line 3: syntax error, unexpected ==, expecting '}'"),
        ("rule a { condition: foo } rule b { condition: true } rule c { condition: bar }", "line 1: undefined identifier \"bar\""),
        ("rule a { condition: foo } rule b { strings: $a=\"x\" nocase nocase condition: $a } ", "line 1: duplicated modifier"),
        ("rule a { condition: foo } xyz", "line 1: undefined identifier \"foo\""),
        ("rule a { condition: foo } rule", "line 1: undefined identifier \"foo\""),
        ("rule a { strings: $a = \"x\" private condition: bar } rule b { condition: baz }", "line 1: undefined identifier \"baz\""),
        ("rule a { condition: $a } private rule b { condition: baz }", "line 1: undefined identifier \"baz\""),
        ("rule { condition: true }", "line 1: syntax error, unexpected '{', expecting identifier"),
        ("rule a { condition: true } rule b { condition: 1 +  }", "line 1: syntax error, unexpected '}'"),
        ("rule a { condition: 5 < }", "line 1: syntax error, unexpected '}'"),
        ("rule a { condition: ( }", "line 1: syntax error, unexpected '}'"),
        ("rule a { meta: a = b condition: true }", "line 1: syntax error, unexpected identifier"),
        ("rule a { meta: a = -\"x\" condition: true }", "line 1: syntax error, unexpected text string, expecting integer number"),
        ("rule a : { condition: true }", "line 1: syntax error, unexpected '{', expecting identifier"),
        ("rule a { condition: true } }", "line 1: syntax error, unexpected '}'"),
        ("rule a { condition: }", "line 1: syntax error, unexpected '}'"),
        ("rule a { strings: condition: true }", "line 1: syntax error, unexpected <condition>, expecting string identifier"),
        ("rule a { strings: $a = condition: true }", "line 1: syntax error, unexpected <condition>, expecting text string"),
        ("rule a { strings: $a = \"x\" condition: $a at }", "line 1: syntax error, unexpected '}'"),
        ("rule a { strings: $a = \"x\" condition: any of }", "line 1: syntax error, unexpected '}', expecting <them> or '('"),
        ("global private global rule a { condition: true }", "OK"),
        ("rule a { condition: true } \n\n rule a { condition: true }", "line 3: duplicated identifier \"a\""),
        ("import \"pe\" rule a { condition: true }", "line 1: modules are not supported"),
    ];
    let mut bad = Vec::new();
    for (src, want) in cases {
        let got = err(src);
        if got != *want {
            bad.push(format!("{src:?}\n   want {want:?}\n   got  {got:?}"));
        }
    }
    assert!(bad.is_empty(), "mismatches:\n{}", bad.join("\n"));
}

#[test]
fn yara_rules_never_panic_on_garbage() {
    let pieces = [
        "rule", "a", "b", "{", "}", "(", ")", "condition", ":", "strings", "meta", "$a", "=", "\"x\"", "and", "or",
        "not", "for", "any", "all", "of", "them", "in", "..", "1", "0", "#a", "@a", "!a", "[", "]", ",", "+", "-",
        "*", "\\", "%", "<<", ">>", "~", "&", "|", "^", "==", "<", "at", "filesize", "uint8", "/x/", "{ 41 }",
        "i", "$", "#", "@", "!", "defined", "matches", "contains", "private", "global", "wide", "xor", "(1..2)",
        "entrypoint", "1.5", "true", "\n", "\"", "/*", "*/", "//",
    ];
    let mut seed = 0x9E37_79B9u32;
    for _ in 0..3000 {
        let mut s = String::new();
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        let n = 3 + (seed % 40) as usize;
        for _ in 0..n {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            s.push_str(pieces[(seed as usize) % pieces.len()]);
            s.push(' ');
        }
        if let Ok(r) = Rules::compile(&s) {
            let ms: Vec<Vec<Match>> = (0..r.string_defs().len()).map(|i| vec![m(i, 1), m(i + 3, 2)]).collect();
            let _ = r.evaluate(b"some data 0123456789", &ms);
        }
        let wrapped = format!("rule r {{ strings: $a = \"x\" condition: $a and ({s}) }}");
        if let Ok(r) = Rules::compile(&wrapped) {
            let _ = r.evaluate(b"MZ\x90\x00", &[vec![m(1, 1)]]);
        }
    }
    // Deep nesting is rejected, not a stack overflow.
    let deep = format!("rule a {{ condition: {}true{} }}", "(".repeat(5000), ")".repeat(5000));
    assert!(Rules::compile(&deep).is_err());
    let deep = format!("rule a {{ condition: {}1 }}", "-".repeat(5000));
    assert!(Rules::compile(&deep).is_err());
    let deep = format!("rule a {{ condition: {}true }}", "not ".repeat(5000));
    assert!(Rules::compile(&deep).is_err());
    // Long flat chains are fine.
    let chain = format!("rule a {{ condition: 1{} == 5001 }}", " + 1".repeat(5000));
    assert!(t_src(&chain));
}

fn t_src(src: &str) -> bool {
    !names(src, b"", &[]).is_empty()
}

/// The nesting caps keep compilation well inside a small thread stack.
#[test]
fn yara_rules_max_depth_fits_small_stack() {
    let stack_kb: usize = std::env::var("RSVOL_YARA_STACK_KB").ok().and_then(|v| v.parse().ok()).unwrap_or(2048);
    let run = || {
        // Every construct below uses exactly MAX_DEPTH - 1 nesting units.
        let n = parser::MAX_DEPTH - 1;
        let srcs = [
            format!("rule a {{ condition: {}true{} }}", "(".repeat(n), ")".repeat(n)),
            format!("rule a {{ condition: {}1 }}", "-".repeat(n)),
            format!("rule a {{ condition: {}true }}", "not ".repeat(n)),
            format!("rule a {{ condition: {}1{} }}", "(~(".repeat(n / 3), "))".repeat(n / 3)),
            format!("rule a {{ condition: 1 + {}1{} }}", "(1 * (".repeat(n / 4), "))".repeat(n / 4)),
            format!("rule a {{ condition: uint8({}0{}) }}", "uint8(".repeat(n - 1), ")".repeat(n - 1)),
            format!("rule a {{ condition: \"a\" matches /{}a{}/ }}", "(".repeat(199), ")".repeat(199)),
        ];
        for s in &srcs {
            let r = Rules::compile(s);
            assert!(r.is_ok(), "{:?}", r.err());
            let _ = r.map(|r| r.evaluate(b"abc", &[]));
        }
        // One level deeper fails cleanly.
        let m = parser::MAX_DEPTH + 1;
        let deep = format!("rule a {{ condition: {}true{} }}", "(".repeat(m), ")".repeat(m));
        assert!(Rules::compile(&deep).is_err());
    };
    let h = std::thread::Builder::new().stack_size(stack_kb * 1024).spawn(run).unwrap();
    assert!(h.join().is_ok());
}

/// libyara `required_strings` per rule (grammar.y counting rules).
#[test]
fn yara_rules_required_strings() {
    let req = |cond: &str| -> bool {
        let src = format!("rule r {{ strings: $a = \"x\" $b = \"y\" condition: ({cond}) or ($a and $b and false) }}");
        let direct = format!("rule r {{ strings: $a = \"x\" $b = \"y\" condition: {cond} and ($a or $b or true) }}");
        let r1 = Rules::compile(&src).unwrap_or_else(|e| panic!("{cond}: {e}"));
        let r2 = Rules::compile(&direct).unwrap_or_else(|e| panic!("{cond}: {e}"));
        // `X or (2 required)` = min(req(X), 2); `X and (min(1,1,0)=0)` = req(X).
        assert_eq!(r1.rules[0].required, r2.rules[0].required, "{cond}");
        r2.rules[0].required
    };
    assert!(req("$a"));
    assert!(req("$a at 5"));
    assert!(req("$a in (0..5)"));
    assert!(req("any of them"));
    assert!(req("all of ($a, $b)"));
    assert!(req("2 of them"));
    assert!(req("(1 + 1) of them in (0..10)"));
    assert!(req("any of them at 0"));
    assert!(req("$a and true"));
    assert!(req("($a or $b) and not $a"));
    assert!(!req("none of them"));
    assert!(!req("0 of them"));
    assert!(!req("#a of them"));
    assert!(!req("50% of them"));
    assert!(!req("not $a"));
    assert!(!req("$a or true"));
    assert!(!req("true"));
    assert!(!req("#a == 0"));
    assert!(!req("for any of them : ($)"));
    assert!(!req("defined $a"));
    // Skipping a required rule when nothing matched changes nothing, also for
    // global rules (their namespace becomes unsatisfied either way).
    let src = r#"global rule g { strings: $a = "x" condition: $a } rule other { condition: true }"#;
    assert!(names(src, b"", &[vec![]]).is_empty());
    assert_eq!(names(src, b"", &[vec![m(0, 1)]]), vec!["g", "other"]);
}

#[test]
fn yara_rules_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Rules>();
    // Evaluation from several threads at once.
    let r = Rules::compile(r#"rule a { strings: $a = "x" condition: for all i in (1..#a) : (@a[i] >= 0) }"#).unwrap();
    std::thread::scope(|s| {
        for t in 0..4 {
            let r = &r;
            s.spawn(move || {
                for i in 0..200 {
                    let ms = vec![(0..(i + t) % 7).map(|k| m(k, 1)).collect::<Vec<_>>()];
                    let out = r.evaluate(b"xxxxxxxx", &ms);
                    assert_eq!(out.len(), usize::from(!ms[0].is_empty()));
                }
            });
        }
    });
}
