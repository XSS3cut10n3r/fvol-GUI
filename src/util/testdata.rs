//! Where tests find the untracked test data: `testdata/` (images, ISF files), `bench/ref/`
//! (python volatility3 reference outputs), `volatility3/` (python's source). It lives in the main
//! checkout, found through git so that linked worktrees share it; `FASTVOL_DATA` overrides.
//! Tests that need a file skip themselves or are `#[ignore]`d when it is missing.

/// The main Windows test image (x64 build 22000, 5 GiB), relative to [`root`].
pub const WIN_IMAGE: &str = "testdata/images/windows/memory-dirty.raw";

/// The checkout holding the test data: `FASTVOL_DATA`, else the main checkout of the repository
/// this crate is built from, else the crate itself (a source tree without git).
pub fn root() -> &'static str {
    static ROOT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        if let Ok(d) = crate::util::env::var("DATA") {
            return d;
        }
        let manifest = env!("CARGO_MANIFEST_DIR");
        std::process::Command::new("git")
            .args(["-C", manifest, "rev-parse", "--path-format=absolute", "--git-common-dir"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| {
                let common = std::path::PathBuf::from(String::from_utf8(o.stdout).ok()?.trim_end());
                Some(common.parent()?.to_str()?.to_string())
            })
            .unwrap_or_else(|| manifest.to_string())
    })
}

/// `rel` (e.g. `testdata/symbols`) under [`root`].
pub fn path(rel: &str) -> String {
    format!("{}/{rel}", root())
}

/// The main Windows test image, [`WIN_IMAGE`] under [`root`].
pub fn win_image() -> String {
    path(WIN_IMAGE)
}
