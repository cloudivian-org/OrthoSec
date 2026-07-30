struct ToolSpec {
    write_text: Vec<String>,
}

fn tool_available(spec: &ToolSpec) -> bool {
    let mut cmd = Command::new(spec.write_text[0].clone());
    cmd.arg("--version").status().is_ok()
}
