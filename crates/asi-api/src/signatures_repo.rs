//! Pobieranie sygnatur FingerprintHub v4 z publicznego repozytorium GitHub
//! (domyślnie `0x727/FingerprintHub`) albo z lokalnego katalogu (środowiska air-gapped).
//!
//! Źródło wybiera konfiguracja: `ASI_FINGERPRINTHUB_LOCAL_DIR` ma priorytet nad
//! pobraniem tarballa z `codeload.github.com`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use flate2::read::GzDecoder;
use tar::Archive;

use crate::config::SignatureSyncConfig;

/// Limit liczby plików YAML pobieranych z repo (ochrona przed patologicznymi archiwami).
pub const MAX_REPO_FILES: usize = 5000;
/// Limit rozmiaru pojedynczego pliku YAML.
pub const MAX_FILE_BYTES: u64 = 512 * 1024;

/// Zwraca zawartości plików `.yaml`/`.yml` sygnatur z repo (lub katalogu lokalnego).
pub async fn load_repo_yaml_files(cfg: &SignatureSyncConfig) -> Result<Vec<String>, String> {
    if let Some(dir) = &cfg.local_dir {
        return load_from_local_dir(Path::new(dir), &cfg.dir);
    }
    fetch_repo_tarball(cfg).await
}

fn load_from_local_dir(root: &Path, dir: &str) -> Result<Vec<String>, String> {
    // Jeśli katalog wskazuje na checkout repo, zejdź do podkatalogu `dir` (np. `fingerprints/`).
    let base: PathBuf = {
        let sub = root.join(dir.trim_matches('/'));
        if sub.is_dir() {
            sub
        } else {
            root.to_path_buf()
        }
    };
    let mut out = Vec::new();
    collect_yaml(&base, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_yaml(dir: &Path, out: &mut Vec<String>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| format!("file_type: {e}"))?;
        if file_type.is_dir() {
            collect_yaml(&path, out)?;
        } else if file_type.is_file() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.ends_with(".yaml") || name.ends_with(".yml") {
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| format!("read {}: {e}", path.display()))?;
                if (content.len() as u64) <= MAX_FILE_BYTES && !content.trim().is_empty() {
                    out.push(content);
                    if out.len() >= MAX_REPO_FILES {
                        return Ok(());
                    }
                }
            }
        }
    }
    Ok(())
}

async fn fetch_repo_tarball(cfg: &SignatureSyncConfig) -> Result<Vec<String>, String> {
    let url = format!(
        "https://codeload.github.com/{}/tar.gz/refs/heads/{}",
        cfg.repo, cfg.git_ref
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("http client build failed: {e}"))?;
    let bytes = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("GET {url}: HTTP {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("read body {url}: {e}"))?;
    parse_repo_tarball(&bytes, &cfg.dir)
}

/// Parsuje tarball GitHub (struktura `<repo>-<ref>/...`) i filtruje pliki YAML
/// spod katalogu `dir_prefix` (np. `fingerprints/`).
pub fn parse_repo_tarball(bytes: &[u8], dir_prefix: &str) -> Result<Vec<String>, String> {
    let decoder = GzDecoder::new(bytes);
    let mut archive = Archive::new(decoder);
    let prefix = {
        let trimmed = dir_prefix.trim().trim_matches('/');
        if trimmed.is_empty() {
            String::new()
        } else {
            format!("{trimmed}/")
        }
    };
    let mut out = Vec::new();
    for entry in archive.entries().map_err(|e| format!("tar entries: {e}"))? {
        let entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("tar path: {e}"))?
            .to_string_lossy()
            .replace('\\', "/");
        // Pomiń pierwszy komponent ścieżki (katalog główny archiwum, np. `FingerprintHub-main/`).
        let rel = match path.split_once('/') {
            Some((_, rest)) => rest,
            None => continue,
        };
        if !prefix.is_empty() && !rel.starts_with(&prefix) {
            continue;
        }
        let lower = rel.to_lowercase();
        if !(lower.ends_with(".yaml") || lower.ends_with(".yml")) {
            continue;
        }
        if out.len() >= MAX_REPO_FILES {
            break;
        }
        let mut buf = String::new();
        entry
            .take(MAX_FILE_BYTES)
            .read_to_string(&mut buf)
            .map_err(|e| format!("read {rel}: {e}"))?;
        if !buf.trim().is_empty() {
            out.push(buf);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn build_tarball() -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let yaml = "id: test-sig\ninfo:\n  name: Test\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(yaml.len() as u64);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "FingerprintHub-main/fingerprints/a.yaml",
                    yaml.as_bytes(),
                )
                .expect("append yaml");
            let readme = "hello";
            let mut h2 = tar::Header::new_gnu();
            h2.set_size(readme.len() as u64);
            h2.set_cksum();
            builder
                .append_data(&mut h2, "FingerprintHub-main/README.md", readme.as_bytes())
                .expect("append readme");
            builder.finish().expect("tar finish");
        }
        let mut gz = Vec::new();
        let mut enc = GzEncoder::new(&mut gz, Compression::fast());
        enc.write_all(&tar_buf).expect("gzip write");
        enc.finish().expect("gzip finish");
        gz
    }

    #[test]
    fn parses_only_yaml_under_prefix() {
        let files = parse_repo_tarball(&build_tarball(), "fingerprints").expect("parse");
        assert_eq!(files.len(), 1);
        assert!(files[0].contains("id: test-sig"));
        assert!(parse_repo_tarball(&build_tarball(), "inny-katalog")
            .expect("parse")
            .is_empty());
    }

    #[test]
    fn loads_yaml_from_local_dir() {
        let dir = std::env::temp_dir().join(format!("asi-sig-test-{}", std::process::id()));
        let sub = dir.join("fingerprints");
        std::fs::create_dir_all(&sub).expect("mkdir");
        std::fs::write(sub.join("b.yml"), "id: b\n").expect("write");
        std::fs::write(dir.join("ignore.txt"), "x").expect("write txt");
        let files = load_from_local_dir(&dir, "fingerprints").expect("load");
        assert_eq!(files.len(), 1);
        assert!(files[0].contains("id: b"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
