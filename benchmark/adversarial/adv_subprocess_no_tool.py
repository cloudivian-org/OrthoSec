# FP stress: subprocess in a plain build script, NOT exposed as a model tool.
import subprocess


def build_project():
    subprocess.run(["make", "build"], check=True)
