Common brief for optimization agents (hardware-floor pass)

You are a PERFORMANCE engineer on "fastvol" (formerly rsvol): a finished, zero-dependency (Rust std only,
no crates ever) rewrite of python volatility3 2.28.2, byte-identical to python on 31 test images. The owner's goal:
"get a majority of the code as close as it can be to the hardware floor ... ensure the changes do not break tests /
general functionality". Six reviewers measured floors and prototyped fixes: read /home/user/rs-vol/bench/reviews/*.md
(yours especially) and the prototype patch named in your task.

RULES
- Work in your git worktree (isolation). If your cwd is not a checkout of /home/user/rs-vol, clone it under
  /home/user/rs-vol/testdata/scratch/opt-<you>/ and work on a new branch there.
- Read /home/user/rs-vol/DESIGN.md (MANDATORY "Resource safety": build/test ONLY via /home/user/rs-vol/bench/scripts/cargo.sh;
  heavy runs via bench/scripts/limit.sh; python ≤ 1 at a time with a private --cache-path; scratch on disk under
  testdata/scratch/, never /tmp (RAM); never load images into RAM). The machine is shared and noisy: measure with
  interleaved A/B runs, best-of-N, CPU cycles/instructions where wall time is noisy, pin with taskset where useful.
- Stay inside your OWNED files (listed in your task). Other agents own other areas and are working concurrently.
  Merge main often (`git fetch /home/user/rs-vol main && git merge FETCH_HEAD`); keep changes surgical.
- Output must stay byte-identical. GATES (must pass before you finish; run targeted checks while iterating and the
  full set at the end, since they take a while on a loaded box):
    bench/scripts/cargo.sh test --profile fast
    bench/scripts/check_all.sh -b $PWD/target/release/fvol            (main Windows image, 98/98)
    bench/scripts/check_win_images.sh -b $PWD/target/release/fvol     (13 more Windows images, 0 DIFF)
    bench/scripts/check_nix.sh -b $PWD/target/release/fvol all        (17 Linux/mac images, 0 DIFF)
  plus the gate runs with an empty private cache (FASTVOL_CACHE=<scratch dir>) where your change touches caching or
  first-run paths. Add unit tests for new code paths. Never weaken a test to make it pass.
- Commit with conventional commits, each ending with "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>".
- FINAL REPLY: branch name; each optimization with before/after numbers (and the floor from the review, i.e. how close
  you now are); gate results; anything left and why.
