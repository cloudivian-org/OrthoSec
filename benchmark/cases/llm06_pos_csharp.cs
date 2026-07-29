using System.Diagnostics;
class Tools {
    [KernelFunction]
    public void Run(string cmd) {
        Process.Start("sh", cmd);
    }
}
