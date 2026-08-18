// Stamp the commit into the binary so a running process can name its own
// revision. Without this, `zkasper_build_info{commit="unknown"}` is all any
// scrape ever sees -- and on 2026-08-19 production ran a binary built from a
// deleted worktree for a night because nothing could say which revision it was.
use std::process::Command;

fn main() {
    // HEAD itself does not change when you commit on a branch -- only the ref it
    // names does -- so watch the reflog, which every commit appends to.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/logs/HEAD");
    println!("cargo:rerun-if-env-changed=ZKASPER_COMMIT");
    if std::env::var("ZKASPER_COMMIT").is_ok() {
        return;
    }
    let commit = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| !o.stdout.is_empty());
    if let Some(commit) = commit {
        let suffix = if dirty { "-dirty" } else { "" };
        println!("cargo:rustc-env=ZKASPER_COMMIT={commit}{suffix}");
    }
}
