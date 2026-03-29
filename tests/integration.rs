use assert_cmd::Command;
use predicates::prelude::*;
use std::process;

struct DockerFixture {
    bridge: String,
}

impl DockerFixture {
    fn new() -> Self {
        let _ = process::Command::new("bash")
            .arg("tests/docker_teardown.sh")
            .output();

        process::Command::new("bash")
            .arg("tests/docker_setup.sh")
            .status()
            .expect("failed to run docker_setup.sh - is Docker running?");

        std::thread::sleep(std::time::Duration::from_secs(2));

        let output = process::Command::new("docker")
            .args(["network", "inspect", "testnet", "--format", "{{.Id}}"])
            .output()
            .expect("failed to inspect docker network");

        let id = String::from_utf8(output.stdout).expect("invalid utf8 from docker inspect");
        let bridge = format!("br-{}", &id.trim()[..12]);

        Self { bridge }
    }
}

impl Drop for DockerFixture {
    fn drop(&mut self) {
        process::Command::new("bash")
            .arg("tests/docker_teardown.sh")
            .status()
            .expect("failed to run docker_teardown.sh");
    }
}

#[test]
#[ignore]
fn integration_discovers_docker_network() {
    let fixture = DockerFixture::new();

    let output = Command::cargo_bin("discovery")
        .unwrap()
        .arg(&fixture.bridge)
        .assert()
        .success()
        .stdout(predicate::str::contains("IP"))
        .stdout(predicate::str::contains("MAC"))
        .stdout(predicate::str::contains("Vendor"))
        .stdout(predicate::str::contains("Latency"))
        .stdout(predicate::str::contains("Method"))
        .stdout(predicate::str::contains("2 hosts discovered"))
        .stdout(predicate::str::contains("192.168.99.2"))
        .stdout(predicate::str::contains("192.168.99.3"))
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let ip_rows: Vec<_> = stdout
        .lines()
        .filter(|l| l.contains("| 192.168.99."))
        .collect();

    assert_eq!(
        ip_rows.len(),
        2,
        "expected exactly 2 IP rows, got: {:#?}",
        ip_rows
    );
}

#[test]
#[ignore]
fn no_args_prints_usage() {
    Command::cargo_bin("discovery")
        .unwrap()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
#[ignore]
fn invalid_interface_returns_error() {
    Command::cargo_bin("discovery")
        .unwrap()
        .arg("doesnotexist0")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
#[ignore]
fn results_are_consistent_across_runs() {
    let fixture = DockerFixture::new();

    let run = |fixture: &DockerFixture| {
        String::from_utf8(
            Command::cargo_bin("discovery")
                .unwrap()
                .arg(&fixture.bridge)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
    };

    let first = run(&fixture);
    let second = run(&fixture);

    for ip in ["192.168.99.2", "192.168.99.3"] {
        assert!(first.contains(ip));
        assert!(second.contains(ip));
    }
}
