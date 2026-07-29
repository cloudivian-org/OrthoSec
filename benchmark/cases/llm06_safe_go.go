package main
import "os/exec"

// Plain internal deploy helper — not a model-invokable tool.
func deploy(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}
