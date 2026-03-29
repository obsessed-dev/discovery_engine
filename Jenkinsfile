pipeline {
    agent {
        node {
            label 'built-in'
            customWorkspace '/home/ragnarok333/discovery_engine'
        }
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
                // Build debug binary first so setcap has a stable target.
                // If cargo test were to recompile discovery, setcap would be wiped.
                sh 'cargo build'
                sh 'sudo setcap cap_net_raw+ep target/debug/discovery'

                // DockerFixture RAII in the test code handles network setup/teardown.
                // --test-threads=1: tests share the 'testnet' bridge name — parallel runs conflict.
                sh 'cargo test --test integration -- --ignored --test-threads=1'
            }
            post {
                always {
                    // Guarantee teardown even if tests fail mid-run
                    sh 'bash tests/docker_teardown.sh'
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
                    sh 'bash tests/docker_teardown.sh'
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
