pipeline {
    agent {
        node {
            label 'built-in'
            customWorkspace '/home/ragnarok333/discovery_engine'
        }
    }

    options {
        skipDefaultCheckout()
    }

    environment {
        CARGO_HOME  = '/var/lib/jenkins/.cargo'
        RUSTUP_HOME = '/var/lib/jenkins/.rustup'
        PATH        = "/var/lib/jenkins/.cargo/bin:${env.PATH}"
        RUST_LOG    = 'warn'
    }

    stages {

        stage('Build Release') {
            steps {
                sh 'cargo build --release'
            }
        }

        stage('Unit Tests') {
            steps {
                // No root needed — pure logic tests
                sh 'cargo test --lib'
            }
        }

        stage('Integration Tests') {
            steps {
                // Compile everything under the test profile without running.
                // Must use --no-run here rather than 'cargo build' — cargo test uses
                // a separate 'test' profile that recompiles the discovery binary with
                // different flags. If we setcap after 'cargo build' (dev profile) and
                // then 'cargo test' recompiles under the test profile, the caps are wiped.
                sh 'cargo test --test integration --no-run'
                sh 'sudo setcap cap_net_raw+ep target/debug/discovery'

                // DockerFixture RAII in the test code handles network setup/teardown.
                // --test-threads=1: tests share the 'testnet' bridge name — parallel runs conflict.
                sh 'cargo test --test integration -- --ignored --test-threads=1'
            }
            post {
                always {
                    // Safety net teardown — DockerFixture::drop() normally handles this,
                    // but may not run if the process is killed hard.
                    // || true: prevents post-stage failure if network is already gone.
                    sh 'bash tests/docker_teardown.sh || true'
                }
            }
        }

        stage('Stress Test') {
            steps {
                script {
                    // Repeat integration suite to stress-test threading, merge logic,
                    // and the 3-second sweep timeout under repeated load.
                    // setcap persists — no rebuild between runs.
                    int runs = 5
                    for (int i = 1; i <= runs; i++) {
                        echo "--- Stress run ${i} of ${runs} ---"
                        sh 'cargo test --test integration -- --ignored --test-threads=1'
                    }
                }
            }
            post {
                always {
                    sh 'bash tests/docker_teardown.sh || true'
                }
            }
        }

        stage('Archive') {
            steps {
                archiveArtifacts artifacts: 'target/release/discovery', fingerprint: true
            }
        }
    }

    post {
        success { echo 'Pipeline complete — binary archived.' }
        failure { echo 'Pipeline failed — check stage logs above.' }
    }
}
