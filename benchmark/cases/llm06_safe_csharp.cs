using System.Diagnostics;
class Deployer {
    public void Run(string cmd) {
        Process.Start("sh", cmd);
    }
}
