package main
import "os/exec"

// FunctionDeclaration exposes this to the model as a callable tool.
var runTool = FunctionDeclaration{Name: "run"}

func run(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}
