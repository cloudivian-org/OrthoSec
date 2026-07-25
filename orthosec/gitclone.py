"""Clone a remote git repository (optionally private) to a temporary directory so a
scan can run against it, then clean up.

Security: a credential is never placed on the git command line or written into logs.
- SSH URLs (`git@host:owner/repo`, `ssh://…`) authenticate through the user's ssh-agent.
- HTTPS URLs use the user's existing git credential helper (gh / osxkeychain / …) by
  default — OrthoSec handles no secret at all.
- An explicit token (from `--git-token-stdin` or an env var) is passed to git only via
  `GIT_ASKPASS` and the child process environment, so it never appears in argv (visible
  in `ps`) and is never written to disk in the helper script.

The temporary clone is shallow (`--depth 1`) and removed after use.
"""
from __future__ import annotations

import contextlib
import os
import re
import shutil
import stat
import subprocess
import tempfile


class CloneError(RuntimeError):
    """A remote repository could not be cloned (bad URL, auth failure, git missing)."""


# git URL forms: scp-style git@host:owner/repo(.git), and ssh:// git:// https:// http://
_URL_RE = re.compile(r"(?i)^(git@[\w.-]+:.+|(?:ssh|git|https?|file)://.+)$")
# `owner/repo` shorthand -> GitHub
_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9][\w.-]*/[A-Za-z0-9][\w.-]*$")

# Env vars a token is read from, in order (highest priority first).
TOKEN_ENV_VARS = ("ORTHOSEC_GIT_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN")


def looks_remote(target: str) -> bool:
    """True when `target` should be cloned rather than opened as a local path.

    An existing local path always wins, so a checked-out directory is never mistaken
    for a URL. A bare `owner/repo` is treated as a GitHub shorthand only when no local
    path by that name exists.
    """
    if not target:
        return False
    if os.path.exists(target):
        return False
    if _URL_RE.match(target):
        return True
    return bool(_SHORTHAND_RE.match(target))


def normalize_url(target: str) -> str:
    """Expand an `owner/repo` shorthand to a GitHub HTTPS URL; pass real URLs through."""
    if _SHORTHAND_RE.match(target) and not _URL_RE.match(target):
        return f"https://github.com/{target}.git"
    return target


def redact(text: str) -> str:
    """Strip any embedded `user:secret@` credentials from a URL / message for logging."""
    return re.sub(r"(://)[^/@\s]*@", r"\1", text or "")


def token_from_env(env=None):
    """Return the first git token found among the supported env vars, or None."""
    env = os.environ if env is None else env
    for key in TOKEN_ENV_VARS:
        val = env.get(key)
        if val:
            return val
    return None


def _is_https(url: str) -> bool:
    return url.lower().startswith(("https://", "http://"))


# Per-host default username for token auth (the token itself is the password):
#   GitHub PAT  -> x-access-token   GitLab PAT -> oauth2   Bitbucket token -> x-token-auth
_HOST_USERNAME = (("github", "x-access-token"),
                  ("gitlab", "oauth2"),
                  ("bitbucket", "x-token-auth"))


def _host_of(url: str) -> str:
    m = re.match(r"(?i)^git@([\w.-]+):", url) or re.match(r"(?i)^[a-z]+://(?:[^@/]*@)?([\w.-]+)", url)
    return m.group(1).lower() if m else ""


def default_username(url: str) -> str:
    """Best default token username for the URL's host (GitHub / GitLab / Bitbucket),
    falling back to `x-access-token`. Overridden by an explicit --git-username."""
    host = _host_of(url)
    for key, user in _HOST_USERNAME:
        if key in host:
            return user
    return "x-access-token"


@contextlib.contextmanager
def _askpass_env(username: str, token: str):
    """Yield env overrides that feed git a username/token through GIT_ASKPASS.

    The helper script contains no secret — it only echoes values from the environment,
    which lives in the git child process alone (never argv, never a file on disk).
    """
    tmp = tempfile.mkdtemp(prefix="orthosec-askpass-")
    try:
        script = os.path.join(tmp, "askpass.sh")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(
                "#!/bin/sh\n"
                'case "$1" in\n'
                '  *[Uu]sername*) printf %s "$ORTHOSEC_GIT_USER" ;;\n'
                '  *) printf %s "$ORTHOSEC_GIT_PASS" ;;\n'
                "esac\n"
            )
        os.chmod(script, stat.S_IRWXU)  # 0700 — owner only
        yield {
            "GIT_ASKPASS": script,
            "ORTHOSEC_GIT_USER": username,
            "ORTHOSEC_GIT_PASS": token,
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@contextlib.contextmanager
def clone(target, *, branch=None, token=None, username=None, keep=False, log=None):
    """Shallow-clone `target` into a temp dir, yield the local path, then clean up.

    `token` (optional) authenticates HTTPS remotes via GIT_ASKPASS; SSH remotes ignore
    it and use the ssh-agent. With no token, git's own credential helper is used.
    `keep=True` leaves the clone on disk (prints its path via `log`).
    """
    url = normalize_url(target)
    dest = tempfile.mkdtemp(prefix="orthosec-clone-")
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"  # fail fast instead of hanging on a password prompt

    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags"]
    if branch:
        cmd += ["--branch", branch]
    cmd += ["--", url, dest]

    auth_cm = _askpass_env(username or default_username(url), token) \
        if (token and _is_https(url)) else contextlib.nullcontext({})
    if log:
        log(f"Cloning {redact(url)} …")
    try:
        with auth_cm as extra_env:
            env.update(extra_env)
            try:
                proc = subprocess.run(cmd, env=env, text=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except FileNotFoundError as exc:  # git not installed
                raise CloneError("git is not installed or not on PATH") from exc
        if proc.returncode != 0:
            detail = redact((proc.stderr or proc.stdout or "").strip()) or "unknown error"
            raise CloneError(f"could not clone {redact(url)} — {detail}")
        yield dest
    finally:
        if keep:
            if log:
                log(f"Kept clone at {dest}")
        else:
            shutil.rmtree(dest, ignore_errors=True)
