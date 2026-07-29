use std::process::Command;

fn deploy(cmd: &str) {
    Command::new("sh").arg("-c").arg(cmd).status().unwrap();
}
