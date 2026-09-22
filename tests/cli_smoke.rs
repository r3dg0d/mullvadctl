use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_works() {
    Command::cargo_bin("mullvadctl")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("NOT a VPN client"));
}

#[test]
fn version_works() {
    Command::cargo_bin("mullvadctl")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("mullvadctl"));
}

#[test]
fn completions_bash() {
    Command::cargo_bin("mullvadctl")
        .unwrap()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mullvadctl"));
}

#[test]
fn missing_mullvad_exits_clearly() {
    // Force empty PATH so mullvad cannot be found
    Command::cargo_bin("mullvadctl")
        .unwrap()
        .env("PATH", "/nonexistent")
        .arg("status")
        .assert()
        .failure()
        .stderr(predicate::str::contains("mullvad CLI not found"));
}
