---
name: git-access-setup
description: Diagnose and fix why git can't be used for the devsecops-reviewer security review (git not installed or not on PATH, folder is not a git repository, "dubious ownership"/safe.directory errors, missing user.email, broken repository). Use when the security-review skill reports a git problem, or when the developer asks to set up git so the pre-push security review and push gate work.
argument-hint: "[problem-code]"
allowed-tools: Bash(devsecops-review git-check*) Bash(git --version) Bash(git config --get *) Bash(git rev-parse *) Bash(git status *)
---

# Git access setup for the security review

The security review needs a working git repository: it computes the scope from
git, stamps the reviewed commit, and the push gate checks that stamp. Your job
is to get git working **with the developer's consent for every change**, then
hand back to the review.

Problem code from the caller, if any: `$ARGUMENTS`

## 1. Diagnose

Run `devsecops-review git-check` (or
`bash "${CLAUDE_PLUGIN_ROOT}/scripts/git-check.sh"` if that command isn't found).
It prints JSON with `ok`, `problem` and `detail`. Explain the problem to the
developer in one or two plain sentences, then follow the matching section.

## 2. Fix, by problem code

Never run a command that changes the machine or the repository without asking
first. Show the exact command, say what it does, and wait for a yes.

### `git_not_found`

Git isn't installed or isn't on PATH. Don't install software yourself; give the
developer the command for their OS:

- Windows: `winget install --id Git.Git -e` (or https://git-scm.com/download/win). Then restart the terminal and Claude Code so PATH is reloaded. Git for Windows also provides the Git Bash shell the plugin's hooks run in.
- macOS: `xcode-select --install` or `brew install git`
- Debian/Ubuntu: `sudo apt-get install git`; Fedora/RHEL: `sudo dnf install git`

If git is installed but not found, PATH is the issue: on Windows check that
`C:\Program Files\Git\cmd` is on PATH.

### `not_a_git_repo`

The current folder isn't inside a git work tree. Ask which applies:

1. **They opened the wrong folder.** Ask for the project path and tell them to restart Claude Code from that folder (or `cd` there).
2. **The project exists in a remote repository.** They should clone it (`git clone <url>`) and work in the clone.
3. **This is a new project that should become a repository.** Offer `git init`, and after that suggest an initial commit. Only run `git init` after an explicit yes.

### `dubious_ownership`

Git refuses the repository because the folder belongs to another user (common
with shared drives, WSL paths, containers, or after copying a folder). Explain
that this is a git safety feature. If the developer confirms they trust this
repository, the fix is to trust **only this path**:

```
git config --global --add safe.directory "<repo path from detail>"
```

Never suggest `safe.directory '*'`.

### `git_error`

Show the `detail` message. Common causes:
- `index.lock` exists: another git process is running, or one crashed. Ask before deleting `.git/index.lock`, and only after confirming no git process is running.
- Corrupted objects / "bad object": stop and recommend re-cloning; don't try repairs.
- Permission denied: the developer must fix file permissions on the folder.

### Missing `user.email` (`user_email_set: false`)

Not fatal for the review, but logs and stamps record the developer by
`git config user.email`. Suggest:
`git config --global user.email "<their work email>"`.

## 3. Hand back

After the fix, run `devsecops-review git-check` again. When `ok` is true, tell
the developer git is ready and offer to run `/devsecops-reviewer:security-review`
now. If it still fails, report what you found and stop; don't loop.
