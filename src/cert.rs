use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose};
use std::fs;
use std::time::Duration;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

use crate::ca::CaStore;
use crate::util;

pub struct CertBundle {
    #[allow(dead_code)]
    pub domain: String,
    pub cert_path: String,
    pub key_path: String,
}

pub fn generate(domain: &str, ca_store: &CaStore, sans: &[String]) -> Result<CertBundle, String> {
    let out_dir = ca_store.dir.join("certs").join(domain);
    fs::create_dir_all(&out_dir).map_err(|e| format!("Cannot create {out_dir:?}: {e}"))?;

    let key_pair = KeyPair::generate().map_err(|e| format!("Cannot generate key: {e}"))?;

    let mut alt_names = vec![domain.to_string()];
    for san in sans {
        if san != domain {
            alt_names.push(san.clone());
        }
    }
    if !domain.starts_with("*.") {
        alt_names.push(format!("*.{domain}"));
    }

    let mut params = CertificateParams::new(alt_names)
        .map_err(|e| format!("Cannot create params: {e}"))?;
    params.distinguished_name.push(DnType::CommonName, domain);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = ::time::OffsetDateTime::now_utc();
    params.not_after = ::time::OffsetDateTime::now_utc() + Duration::from_secs(365 * 86400);

    let ca_key = ca_store.load_key()?;
    let ca_params = crate::ca::CaStore::ca_params();
    let issuer = Issuer::new(ca_params, &ca_key);

    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(|e| format!("Cannot sign cert: {e}"))?;

    let cert_path = out_dir.join("cert.pem");
    let key_path = out_dir.join("key.pem");

    fs::write(&cert_path, cert.pem()).map_err(|e| format!("Cannot write cert: {e}"))?;
    fs::write(&key_path, key_pair.serialize_pem())
        .map_err(|e| format!("Cannot write key: {e}"))?;

    Ok(CertBundle {
        domain: domain.to_string(),
        cert_path: cert_path.to_string_lossy().to_string(),
        key_path: key_path.to_string_lossy().to_string(),
    })
}

pub fn list(ca_store: &CaStore) -> Result<Vec<String>, String> {
    let certs_dir = ca_store.dir.join("certs");
    if !certs_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut domains = Vec::new();
    for entry in fs::read_dir(&certs_dir).map_err(|e| format!("{e}"))? {
        let entry = entry.map_err(|e| format!("{e}"))?;
        if entry.path().is_dir() && entry.path().join("cert.pem").exists() {
            domains.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    domains.sort();
    Ok(domains)
}

pub fn show(domain: &str, ca_store: &CaStore) -> Result<String, String> {
    let cert_path = ca_store.dir.join("certs").join(domain).join("cert.pem");
    if !cert_path.exists() {
        return Err(format!("No certificate for '{domain}'"));
    }

    let pem_data =
        fs::read_to_string(&cert_path).map_err(|e| format!("Cannot read cert: {e}"))?;
    let der = util::pem_decode(&pem_data)?;
    let parsed = X509Certificate::from_der(&der)
        .map_err(|e| format!("Cannot parse cert: {e}"))?
        .1;

    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("(unknown)");
    let not_before = parsed.validity().not_before.to_datetime();
    let not_after = parsed.validity().not_after.to_datetime();
    let issuer = parsed
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("(unknown)");
    let sans: Vec<String> = parsed
        .subject_alternative_name()
        .map_err(|e| format!("Cannot parse SANs: {e}"))?
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|gn| {
                    if let GeneralName::DNSName(s) = gn {
                        Some(s.to_string())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let mut out = format!("Domain:        {cn}\n");
    out.push_str(&format!("Issuer:        {issuer}\n"));
    out.push_str(&format!("Valid from:    {not_before}\n"));
    out.push_str(&format!("Valid until:   {not_after}\n"));
    out.push_str(&format!("SANs:          {}\n", sans.join(", ")));
    out.push_str(&format!("Cert:          {}\n", cert_path.display()));
    out.push_str(&format!(
        "Key:           {}\n",
        ca_store.dir.join("certs").join(domain).join("key.pem").display()
    ));

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CaStore;
    use std::path::Path;
    use tempfile::tempdir;

    fn setup() -> (CaStore, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let store = CaStore {
            dir: dir.path().to_path_buf(),
            key_path: dir.path().join("ca-key.pem"),
            cert_path: dir.path().join("ca-cert.pem"),
        };
        store.init().unwrap();
        (store, dir)
    }

    #[test]
    fn test_generate_creates_files() {
        let (store, _dir) = setup();
        let bundle = generate("test.local", &store, &[]).unwrap();
        assert!(Path::new(&bundle.cert_path).exists());
        assert!(Path::new(&bundle.key_path).exists());
        assert_eq!(bundle.domain, "test.local");
    }

    #[test]
    fn test_generate_with_sans() {
        let (store, _dir) = setup();
        let _bundle = generate(
            "primary.test",
            &store,
            &["san1.test".to_string(), "san2.test".to_string()],
        )
        .unwrap();
        let info = show("primary.test", &store).unwrap();
        assert!(info.contains("san1.test"));
        assert!(info.contains("san2.test"));
    }

    #[test]
    fn test_list_returns_domains() {
        let (store, _dir) = setup();
        generate("beta.test", &store, &[]).unwrap();
        generate("alpha.test", &store, &[]).unwrap();
        let domains = list(&store).unwrap();
        assert_eq!(domains, vec!["alpha.test", "beta.test"]);
    }

    #[test]
    fn test_list_empty_when_no_certs() {
        let (store, _dir) = setup();
        let domains = list(&store).unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn test_show_returns_info() {
        let (store, _dir) = setup();
        generate("show.test", &store, &[]).unwrap();
        let info = show("show.test", &store).unwrap();
        assert!(info.contains("Domain:        show.test"));
        assert!(info.contains("Issuer:        local-ssl Development CA"));
        assert!(info.contains("Valid from:"));
        assert!(info.contains("Valid until:"));
        assert!(info.contains("SANs:"));
        assert!(info.contains("Cert:"));
        assert!(info.contains("Key:"));
    }

    #[test]
    fn test_show_nonexistent_domain() {
        let dir = tempdir().unwrap();
        let store = CaStore {
            dir: dir.path().to_path_buf(),
            key_path: dir.path().join("ca-key.pem"),
            cert_path: dir.path().join("ca-cert.pem"),
        };
        let result = show("nonexistent.test", &store);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "No certificate for 'nonexistent.test'"
        );
    }
}
