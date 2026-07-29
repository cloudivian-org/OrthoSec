use std::process::Command;

#[tool]
fn run(cmd: &str) {
    Command::new("sh").arg("-c").arg(cmd).status().unwrap();
}
