use std::io::Write;
use std::path::Path;
use std::process::Command;

pub fn install_ca(cert_path: &Path) -> Result<(), String> {
    if cfg!(target_os = "macos") {
        macos_install(cert_path)
    } else if cfg!(target_os = "windows") {
        windows_install(cert_path)
    } else {
        linux_install(cert_path)
    }
}

pub fn is_ca_trusted(cert_path: &Path) -> bool {
    let cert_pem = match std::fs::read_to_string(cert_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let cn = cert_pem
        .lines()
        .find(|l| l.contains("CN="))
        .and_then(|l| l.split("CN=").nth(1))
        .map(|s| s.trim_end_matches('"'))
        .unwrap_or("unknown");

    if cfg!(target_os = "macos") {
        Command::new("security")
            .args(["find-certificate", "-c", cn, "/Library/Keychains/System.keychain"])
            .output()
            .ok()
            .map_or(false, |o| o.status.success())
    } else if cfg!(target_os = "linux") {
        let hash = Command::new("openssl")
            .args(["x509", "-in", &cert_path.to_string_lossy(), "-hash", "-noout"])
            .output()
            .ok()
            .and_then(|o| {
                let h = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if h.is_empty() { None } else { Some(h) }
            });
        match hash {
            Some(h) => {
                let dirs = [
                    "/usr/local/share/ca-certificates",
                    "/etc/pki/ca-trust/source/anchors",
                    "/usr/share/pki/trust/anchors",
                ];
                dirs.iter().any(|d| {
                    Path::new(d).join(format!("{h}.0")).exists()
                        || Path::new(d).join(format!("{h}.p11-kit")).exists()
                })
            }
            None => false,
        }
    } else {
        false
    }
}

fn linux_install(cert_path: &Path) -> Result<(), String> {
    let cert = std::fs::read_to_string(cert_path).map_err(|e| format!("Cannot read CA cert: {e}"))?;

    let dest = if Path::new("/usr/local/share/ca-certificates").is_dir() {
        "/usr/local/share/ca-certificates/local-ssl.crt"
    } else if Path::new("/etc/pki/ca-trust/source/anchors").is_dir() {
        "/etc/pki/ca-trust/source/anchors/local-ssl.pem"
    } else if Path::new("/usr/share/pki/trust/anchors").is_dir() {
        "/usr/share/pki/trust/anchors/local-ssl.pem"
    } else if Path::new("/etc/ca-certificates/trust-source/anchors").is_dir() {
        "/etc/ca-certificates/trust-source/anchors/local-ssl.crt"
    } else {
        return Err("Unsupported Linux distro — install CA manually.".into());
    };

    let mut child = Command::new("cp")
        .arg("--")
        .arg(dest)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Cannot spawn cp: {e}"))?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(cert.as_bytes())
            .map_err(|e| format!("Cannot write cert: {e}"))?;
    }
    child
        .wait_with_output()
        .map_err(|e| format!("cp failed: {e}"))?;

    let update_cmds: &[&[&str]] = &[
        &["update-ca-certificates"],
        &["update-ca-trust"],
        &["trust", "extract-compat"],
    ];

    for args in update_cmds {
        if which(args[0]) {
            let out = Command::new(args[0]).args(&args[1..]).output();
            if out.ok().map_or(false, |o| o.status.success()) {
                return Ok(());
            }
        }
    }

    Err("CA cert copied but trust DB update failed — run manually.".into())
}

fn macos_install(cert_path: &Path) -> Result<(), String> {
    let s = Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
            &cert_path.to_string_lossy(),
        ])
        .status()
        .map_err(|e| format!("Cannot add CA to keychain: {e}"))?;
    if s.success() {
        Ok(())
    } else {
        Err("Failed to install CA in System keychain".into())
    }
}

fn windows_install(cert_path: &Path) -> Result<(), String> {
    let s = Command::new("certutil")
        .args(["-addstore", "Root", &cert_path.to_string_lossy()])
        .status()
        .map_err(|e| format!("Cannot install CA: {e}"))?;
    if s.success() {
        Ok(())
    } else {
        Err("Failed to install CA in Root store".into())
    }
}

fn which(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .ok()
        .map_or(false, |o| o.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_which_existing_command() {
        assert!(which("echo"));
    }

    #[test]
    fn test_which_nonexistent_command() {
        assert!(!which("this-command-definitely-does-not-exist"));
    }
}
