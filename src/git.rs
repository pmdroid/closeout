use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SIGKILL: i32 = 9;

unsafe extern "C" {
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}

pub struct Captured {
    pub code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub spawn_failed: bool,
}

struct RawCaptured {
    code: Option<i32>,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
    spawn_failed: bool,
}

pub fn capture(program: &str, args: &[String], cwd: &Path, timeout: Duration, cap: Option<usize>) -> Captured {
    let raw = capture_raw(program, args, cwd, timeout, cap, &[]);
    Captured {
        code: raw.code,
        timed_out: raw.timed_out,
        stdout: String::from_utf8_lossy(&raw.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&raw.stderr).into_owned(),
        truncated: raw.truncated,
        spawn_failed: raw.spawn_failed,
    }
}

fn capture_raw(
    program: &str,
    args: &[String],
    cwd: &Path,
    timeout: Duration,
    cap: Option<usize>,
    env_vars: &[(&str, &str)],
) -> RawCaptured {
    let mut command = Command::new(program);
    command.args(args).current_dir(cwd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (key, value) in env_vars {
        command.env(key, value);
    }
    unsafe {
        command.pre_exec(|| {
            if setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            return RawCaptured {
                code: None,
                timed_out: false,
                stdout: Vec::new(),
                stderr: Vec::new(),
                truncated: false,
                spawn_failed: true,
            };
        }
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        unsafe {
            kill(child.id() as i32, SIGKILL);
        }
        let _ = child.wait();
        return RawCaptured {
            code: None,
            timed_out: false,
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            spawn_failed: true,
        };
    };
    let stdout_cap = cap;
    let stderr_cap = cap;
    let stdout_handle = thread::spawn(move || read_stream(stdout, stdout_cap));
    let stderr_handle = thread::spawn(move || read_stream(stderr, stderr_cap));
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= timeout => {
                timed_out = true;
                unsafe {
                    kill(-(child.id() as i32), SIGKILL);
                    kill(child.id() as i32, SIGKILL);
                }
                break child.wait().ok();
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => break None,
        }
    };
    let (out_bytes, out_trunc) = stdout_handle.join().unwrap_or_default();
    let (err_bytes, err_trunc) = stderr_handle.join().unwrap_or_default();
    RawCaptured {
        code: status.and_then(|status| status.code()),
        timed_out,
        stdout: out_bytes,
        stderr: err_bytes,
        truncated: out_trunc || err_trunc,
        spawn_failed: false,
    }
}

fn finish_capture(mut raw: RawCaptured) -> Captured {
    if raw.spawn_failed {
        raw.code = Some(127);
    } else if raw.timed_out {
        raw.code = Some(124);
    } else if raw.code.is_none() {
        raw.code = Some(1);
    }
    Captured {
        code: raw.code,
        timed_out: raw.timed_out,
        stdout: String::from_utf8_lossy(&raw.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&raw.stderr).into_owned(),
        truncated: raw.truncated,
        spawn_failed: raw.spawn_failed,
    }
}

pub fn git(cwd: &Path, args: &[String], timeout: Duration) -> Captured {
    finish_capture(capture_raw("git", args, cwd, timeout, None, &[("GIT_TERMINAL_PROMPT", "0")]))
}

pub struct ListedBlob {
    pub mode: String,
    pub object: String,
    pub path: String,
}

pub fn origin_main(cwd: &Path) -> Result<String, String> {
    let fetched = git(cwd, &owned(&["fetch", "--no-tags", "origin", "refs/heads/main"]), Duration::from_secs(120));
    if fetched.code != Some(0) {
        return Err(remote_unavailable(&fetched.stderr));
    }
    let have = resolve_commit(cwd, "FETCH_HEAD").ok_or_else(|| remote_unavailable(&fetched.stderr))?;
    let listed = git(
        cwd,
        &owned(&["ls-remote", "--exit-code", "origin", "refs/heads/main"]),
        Duration::from_secs(60),
    );
    let remote = match remote_sha(&listed) {
        Ok(sha) => sha,
        Err(message) if message.is_empty() => return Err(remote_unavailable(&listed.stderr)),
        Err(message) => return Err(message),
    };
    if have != remote {
        return Err("origin/main is unavailable".to_string());
    }
    Ok(have)
}

pub fn list_blobs(cwd: &Path, commit: &str, prefix: &str) -> Result<Vec<ListedBlob>, String> {
    ls_tree(cwd, &["-r", commit, "--", prefix])
}

pub enum Located {
    Commit(ListedBlob),
    Disk(PathBuf),
    Missing,
}

pub fn locate(cwd: &Path, commit: &str, path: &str) -> Result<Located, String> {
    let mut pending: Vec<String> = path.rsplit('/').map(str::to_string).collect();
    let mut real: Vec<String> = Vec::new();
    let mut found = None;
    let mut hops = 0;
    while let Some(part) = pending.pop() {
        match part.as_str() {
            "" | "." => continue,
            ".." => {
                found = None;
                if real.pop().is_none() {
                    return Ok(Located::Disk(beyond(cwd.join(".."), pending)));
                }
                continue;
            }
            _ => real.push(part),
        }
        let Some(entry) = tree_entry(cwd, commit, &real.join("/"))? else {
            return Ok(Located::Missing);
        };
        if entry.mode != "120000" {
            if entry.mode != "040000" && !pending.is_empty() {
                return Ok(Located::Missing);
            }
            found = Some(entry);
            continue;
        }
        hops += 1;
        if hops > 40 {
            return Err(format!("symlink loop: {path}"));
        }
        real.pop();
        found = None;
        let target = String::from_utf8(read_blob(cwd, &entry.object)?).map_err(|_| "could not read the policy file".to_string())?;
        if target.is_empty() {
            return Ok(Located::Missing);
        }
        if target.starts_with('/') {
            return Ok(Located::Disk(beyond(PathBuf::from(target), pending)));
        }
        pending.extend(target.rsplit('/').map(str::to_string));
    }
    if let Some(entry) = found {
        return Ok(Located::Commit(entry));
    }
    if real.is_empty() {
        return Ok(Located::Commit(ListedBlob {
            mode: "040000".to_string(),
            object: String::new(),
            path: ".".to_string(),
        }));
    }
    Ok(tree_entry(cwd, commit, &real.join("/"))?.map_or(Located::Missing, Located::Commit))
}

pub fn child(dir: &str, name: &str) -> String {
    if dir == "." { name.to_string() } else { format!("{dir}/{name}") }
}

fn beyond(mut base: PathBuf, pending: Vec<String>) -> PathBuf {
    base.extend(pending.into_iter().rev());
    base
}

pub fn tree_entry(cwd: &Path, commit: &str, path: &str) -> Result<Option<ListedBlob>, String> {
    Ok(ls_tree(cwd, &[commit, "--", path])?.into_iter().find(|entry| entry.path == path))
}

fn ls_tree(cwd: &Path, args: &[&str]) -> Result<Vec<ListedBlob>, String> {
    let mut full = vec!["--literal-pathspecs", "-c", "core.quotepath=false", "ls-tree", "-z"];
    full.extend_from_slice(args);
    let raw = capture_raw("git", &owned(&full), cwd, Duration::from_secs(30), None, &[("GIT_TERMINAL_PROMPT", "0")]);
    if raw.spawn_failed || raw.timed_out || raw.code != Some(0) || raw.truncated {
        return Err("could not read the policy file".to_string());
    }
    parse_ls_tree(&raw.stdout)
}

pub fn changed_paths(cwd: &Path, base: &str, head: &str) -> Result<Vec<String>, String> {
    let raw = capture_raw(
        "git",
        &owned(&["diff", "--name-only", "--no-renames", "-z", base, head, "--"]),
        cwd,
        Duration::from_secs(30),
        None,
        &[("GIT_TERMINAL_PROMPT", "0")],
    );
    if raw.spawn_failed || raw.timed_out || raw.code != Some(0) || raw.truncated {
        return Err(paths_unavailable(&raw.stderr));
    }
    let mut paths = Vec::new();
    for record in raw.stdout.split(|byte| *byte == 0) {
        if record.is_empty() {
            continue;
        }
        let path = std::str::from_utf8(record).map_err(|_| "changed paths are unavailable".to_string())?;
        paths.push(path.to_string());
    }
    Ok(paths)
}

pub fn read_blob(cwd: &Path, object: &str) -> Result<Vec<u8>, String> {
    let raw = capture_raw(
        "git",
        &owned(&["cat-file", "blob", object]),
        cwd,
        Duration::from_secs(30),
        None,
        &[("GIT_TERMINAL_PROMPT", "0")],
    );
    if raw.spawn_failed || raw.timed_out || raw.code != Some(0) || raw.truncated {
        return Err("could not read the policy file".to_string());
    }
    Ok(raw.stdout)
}

fn paths_unavailable(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text.lines().find(|line| !line.trim().is_empty()).unwrap_or("").trim();
    if line.is_empty() {
        "changed paths are unavailable".to_string()
    } else {
        format!("changed paths are unavailable: {line}")
    }
}

fn remote_unavailable(stderr: &str) -> String {
    let line = stderr.lines().find(|line| !line.trim().is_empty()).unwrap_or("").trim();
    if line.is_empty() {
        "origin/main is unavailable".to_string()
    } else {
        format!("origin/main is unavailable: {line}")
    }
}

fn remote_sha(captured: &Captured) -> Result<String, String> {
    if captured.code != Some(0) {
        return Err(String::new());
    }
    for line in captured.stdout.lines() {
        let mut parts = line.split_whitespace();
        let Some(sha) = parts.next() else {
            continue;
        };
        let Some(name) = parts.next() else {
            continue;
        };
        let sha = sha.to_ascii_lowercase();
        if name == "refs/heads/main" && is_sha(&sha) {
            return Ok(sha);
        }
    }
    Err("origin/main is unavailable".to_string())
}

fn parse_ls_tree(bytes: &[u8]) -> Result<Vec<ListedBlob>, String> {
    let mut out = Vec::new();
    for record in bytes.split(|byte| *byte == 0) {
        if record.is_empty() {
            continue;
        }
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            return Err("could not read the policy file".to_string());
        };
        let meta = std::str::from_utf8(&record[..tab]).map_err(|_| "could not read the policy file".to_string())?;
        let path = std::str::from_utf8(&record[tab + 1..]).map_err(|_| "could not read the policy file".to_string())?;
        let mut parts = meta.split(' ');
        let mode = parts.next().unwrap_or("");
        let kind = parts.next().unwrap_or("");
        let object = parts.next().unwrap_or("");
        if !matches!(kind, "blob" | "tree" | "commit") || !is_sha(object) || path.is_empty() {
            return Err("could not read the policy file".to_string());
        }
        out.push(ListedBlob {
            mode: mode.to_string(),
            object: object.to_string(),
            path: path.to_string(),
        });
    }
    Ok(out)
}

pub fn resolve_commit(cwd: &Path, rev: &str) -> Option<String> {
    let spec = format!("{rev}^{{commit}}");
    let args = ["rev-parse", "--verify", "--end-of-options", spec.as_str()];
    let result = git(cwd, &owned(&args), Duration::from_secs(30));
    if result.code != Some(0) {
        return None;
    }
    let sha = result.stdout.trim().to_ascii_lowercase();
    if is_sha(&sha) { Some(sha) } else { None }
}

pub fn porcelain(cwd: &Path) -> Option<String> {
    let args = ["status", "--porcelain", "--untracked-files=all"];
    let result = git(cwd, &owned(&args), Duration::from_secs(30));
    if result.code == Some(0) { Some(result.stdout) } else { None }
}

fn owned(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_string()).collect()
}

fn is_sha(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn read_stream(mut reader: impl Read, cap: Option<usize>) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                if truncated {
                    continue;
                }
                match cap {
                    Some(limit) if buf.len() + n > limit => {
                        let room = limit.saturating_sub(buf.len());
                        buf.extend_from_slice(&tmp[..room]);
                        truncated = true;
                    }
                    _ => buf.extend_from_slice(&tmp[..n]),
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    (buf, truncated)
}
