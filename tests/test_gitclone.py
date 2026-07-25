"""Remote-clone support: URL detection, credential redaction, the security property
that an access token never reaches the git command line, and a real local round-trip."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from orthosec import gitclone


def _has_git() -> bool:
    return shutil.which("git") is not None


class TestLooksRemote(unittest.TestCase):
    def test_urls_are_remote(self):
        for u in ("git@github.com:org/repo.git",
                  "https://github.com/org/repo.git",
                  "ssh://git@host/org/repo",
                  "git://host/org/repo"):
            self.assertTrue(gitclone.looks_remote(u), u)

    def test_owner_repo_shorthand_is_remote(self):
        self.assertTrue(gitclone.looks_remote("cloudivian-org/OrthoSec"))

    def test_existing_local_path_is_not_remote(self):
        d = tempfile.mkdtemp()
        try:
            self.assertFalse(gitclone.looks_remote(d))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_plain_word_is_not_remote(self):
        self.assertFalse(gitclone.looks_remote("./src"))
        self.assertFalse(gitclone.looks_remote("some_dir"))


class TestUrlHelpers(unittest.TestCase):
    def test_shorthand_expands_to_github(self):
        self.assertEqual(gitclone.normalize_url("org/repo"),
                         "https://github.com/org/repo.git")

    def test_full_url_passthrough(self):
        u = "https://gitlab.com/org/repo.git"
        self.assertEqual(gitclone.normalize_url(u), u)

    def test_redact_strips_credentials(self):
        self.assertEqual(
            gitclone.redact("https://x-access-token:ghp_secret@github.com/o/r.git"),
            "https://github.com/o/r.git")

    def test_token_from_env(self):
        self.assertEqual(gitclone.token_from_env({"GITHUB_TOKEN": "abc"}), "abc")
        self.assertEqual(
            gitclone.token_from_env({"ORTHOSEC_GIT_TOKEN": "x", "GITHUB_TOKEN": "y"}), "x")
        self.assertIsNone(gitclone.token_from_env({}))


class TestTokenNeverInArgv(unittest.TestCase):
    """The security property: a token is passed via GIT_ASKPASS + env, never in argv."""

    def test_token_absent_from_command_line(self):
        captured = {}

        def fake_run(cmd, env=None, **kw):
            captured["cmd"] = cmd
            captured["env"] = env

            class R:  # emulate a successful clone (dir already made by clone())
                returncode = 0
                stdout = ""
                stderr = ""
            return R()

        orig = subprocess.run
        subprocess.run = fake_run
        try:
            with gitclone.clone("https://github.com/org/repo.git",
                                token="ghp_SUPERSECRET") as local:
                self.assertTrue(os.path.isdir(local))
        finally:
            subprocess.run = orig

        joined = " ".join(captured["cmd"])
        self.assertNotIn("ghp_SUPERSECRET", joined)
        # token is handed over out-of-band
        self.assertIn("GIT_ASKPASS", captured["env"])
        self.assertEqual(captured["env"]["ORTHOSEC_GIT_PASS"], "ghp_SUPERSECRET")
        self.assertEqual(captured["env"]["GIT_TERMINAL_PROMPT"], "0")


@unittest.skipUnless(_has_git(), "git not installed")
class TestRealCloneRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.origin = os.path.join(self.tmp, "origin")
        os.makedirs(self.origin)

        def git(*a):
            subprocess.run(["git", "-C", self.origin, *a], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        subprocess.run(["git", "init", "-q", self.origin], check=True)
        git("config", "user.email", "t@t.t")
        git("config", "user.name", "t")
        Path(self.origin, "agent.py").write_text(
            "def f(client):\n"
            "    out = client.chat.completions.create(messages=[])\n"
            "    __import__('os').system(out.choices[0].message.content)\n")
        git("add", "-A")
        git("commit", "-qm", "init")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_clone_yields_files_then_cleans_up(self):
        url = "file://" + self.origin
        seen = None
        with gitclone.clone(url) as local:
            seen = local
            self.assertTrue(os.path.exists(os.path.join(local, "agent.py")))
        # cleaned up after the context exits
        self.assertFalse(os.path.exists(seen))

    def test_keep_clone_preserved(self):
        url = "file://" + self.origin
        with gitclone.clone(url, keep=True) as local:
            kept = local
        self.assertTrue(os.path.exists(os.path.join(kept, "agent.py")))
        shutil.rmtree(kept, ignore_errors=True)

    def test_bad_url_raises_clone_error(self):
        with self.assertRaises(gitclone.CloneError):
            with gitclone.clone("file://" + self.tmp + "/does-not-exist.git"):
                pass


if __name__ == "__main__":
    unittest.main()
