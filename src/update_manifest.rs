//! Vérification Ed25519 du manifeste de mise à jour (ticket 0050).
//!
//! Le playbook de release signe **hors ligne** un manifeste JSON canonique
//! `{key_id, version, filename, size, sha256}` (octets exacts) ; la signature
//! Ed25519 détachée est publiée à côté (`flowline-<version>.msi.manifest.json.sig`)
//! et servie par l'API en base64 avec les octets exacts du manifeste.
//!
//! Le client :
//! 1. retrouve la clé publique dans le ring embarqué au build
//!    (`config::UPDATE_KEYS`) via `key_id` ;
//! 2. vérifie la signature sur les octets décodés du manifeste ;
//! 3. contrôle version, nom de fichier, taille et SHA-256 du fichier téléchargé.
//!
//! Une API (ou un NPM/DNS) compromise ne peut donc pas forger de mise à jour :
//! la clé privée n'est jamais en ligne. Toute anomalie => erreur (fail closed),
//! le fichier est refusé et supprimé par l'appelant.

use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, bail};
use base64::Engine as _;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::sign;

use crate::ResultType;

/// Manifeste signé d'un artefact de mise à jour.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct UpdateManifest {
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub sha256: String,
}

/// Réponse de `GET /api/update/manifest/{version}` : octets exacts du manifeste
/// et signature, encodés base64.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct UpdateManifestEnvelope {
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub manifest: String,
    #[serde(default)]
    pub sig: String,
}

fn decode_pk(b64: &str) -> Option<sign::PublicKey> {
    let raw = crate::base64::engine::general_purpose::STANDARD
        .decode(b64)
        .ok()?;
    sign::PublicKey::from_slice(&raw)
}

fn sha256_hex_file(path: &Path) -> ResultType<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Vérifie le manifeste contre un ring de clés explicite (testable sans clé de
/// production). Retourne le manifeste validé.
pub fn verify_update_manifest_with_keys(
    keys: &[(&str, &str)],
    envelope: &UpdateManifestEnvelope,
    expected_version: &str,
    file_path: &Path,
) -> ResultType<UpdateManifest> {
    if envelope.key_id.is_empty() {
        bail!("manifeste sans key_id");
    }
    let pk_b64 = keys
        .iter()
        .find(|(id, _)| *id == envelope.key_id)
        .map(|(_, key)| *key)
        .ok_or_else(|| anyhow!("clé de signature inconnue: {}", envelope.key_id))?;
    let pk = decode_pk(pk_b64).ok_or_else(|| anyhow!("clé publique de mise à jour invalide"))?;

    let manifest_bytes = crate::base64::engine::general_purpose::STANDARD
        .decode(&envelope.manifest)
        .map_err(|_| anyhow!("manifeste base64 invalide"))?;
    let sig_bytes = crate::base64::engine::general_purpose::STANDARD
        .decode(&envelope.sig)
        .map_err(|_| anyhow!("signature base64 invalide"))?;
    let sig = sign::Signature::from_bytes(&sig_bytes)
        .map_err(|_| anyhow!("signature de taille invalide"))?;
    if !sign::verify_detached(&sig, &manifest_bytes, &pk) {
        bail!("signature invalide");
    }

    let manifest: UpdateManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| anyhow!("manifeste JSON invalide"))?;
    if manifest.key_id != envelope.key_id {
        bail!("key_id incohérent entre enveloppe et manifeste");
    }
    if manifest.version != expected_version {
        bail!(
            "version du manifeste incohérente ({} != {})",
            manifest.version,
            expected_version
        );
    }
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("nom de fichier invalide"))?;
    if manifest.filename != file_name {
        bail!(
            "nom de fichier du manifeste incohérent ({} != {})",
            manifest.filename,
            file_name
        );
    }
    let size = std::fs::metadata(file_path)?.len();
    if size != manifest.size {
        bail!("taille du fichier incohérente ({} != {})", size, manifest.size);
    }
    let sha256 = sha256_hex_file(file_path)?;
    if !sha256.eq_ignore_ascii_case(&manifest.sha256) {
        bail!("SHA-256 du fichier incohérent");
    }
    Ok(manifest)
}

/// Vérifie le manifeste avec le ring de clés embarqué (`config::UPDATE_KEYS`).
pub fn verify_update_manifest(
    envelope: &UpdateManifestEnvelope,
    expected_version: &str,
    file_path: &Path,
) -> ResultType<UpdateManifest> {
    verify_update_manifest_with_keys(
        crate::config::UPDATE_KEYS,
        envelope,
        expected_version,
        file_path,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const MSI_NAME: &str = "flowline-1.4.18-x86_64.msi";

    /// Fichier de test dans un répertoire unique (le nom doit correspondre à
    /// celui du manifeste signé, il est vérifié).
    fn test_file(tag: &str, data: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hbb_update_manifest_{}_{}",
            std::process::id(),
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(MSI_NAME);
        std::fs::write(&path, data).unwrap();
        path
    }

    fn cleanup(path: &Path) {
        if let Some(dir) = path.parent() {
            std::fs::remove_dir_all(dir).ok();
        }
    }

    /// Génère un couple de clés + une enveloppe signée pour un fichier donné.
    fn signed_envelope(
        key_id: &str,
        version: &str,
        file_name: &str,
        file_data: &[u8],
    ) -> ((String, String), UpdateManifestEnvelope) {
        let (pk, sk) = sign::gen_keypair();
        let pk_b64 = crate::base64::engine::general_purpose::STANDARD.encode(pk.0);
        let sha256: String = Sha256::digest(file_data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let manifest = UpdateManifest {
            key_id: key_id.to_string(),
            version: version.to_string(),
            filename: file_name.to_string(),
            size: file_data.len() as u64,
            sha256,
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let sig = sign::sign_detached(&manifest_bytes, &sk);
        let envelope = UpdateManifestEnvelope {
            key_id: key_id.to_string(),
            manifest: crate::base64::engine::general_purpose::STANDARD.encode(&manifest_bytes),
            sig: crate::base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        };
        ((key_id.to_string(), pk_b64), envelope)
    }

    #[test]
    fn verify_ok() {
        let data = b"MSI factice";
        let path = test_file("ok", data);
        let (key, envelope) = signed_envelope("fl-test", "1.4.18", "flowline-1.4.18-x86_64.msi", data);
        let keys = [(&key.0[..], &key.1[..])];
        let m = verify_update_manifest_with_keys(&keys, &envelope, "1.4.18", &path).unwrap();
        assert_eq!(m.sha256.len(), 64);
        cleanup(&path);
    }

    #[test]
    fn reject_tampered_manifest() {
        let data = b"MSI factice";
        let path = test_file("tamper", data);
        let (key, mut envelope) =
            signed_envelope("fl-test", "1.4.18", "flowline-1.4.18-x86_64.msi", data);
        let mut raw = crate::base64::engine::general_purpose::STANDARD
            .decode(&envelope.manifest)
            .unwrap();
        raw[10] ^= 0x01;
        envelope.manifest = crate::base64::engine::general_purpose::STANDARD.encode(&raw);
        let keys = [(&key.0[..], &key.1[..])];
        assert!(verify_update_manifest_with_keys(&keys, &envelope, "1.4.18", &path).is_err());
        cleanup(&path);
    }

    #[test]
    fn reject_unknown_key_id() {
        let data = b"MSI factice";
        let path = test_file("keyid", data);
        let (_key, envelope) =
            signed_envelope("fl-2027", "1.4.18", "flowline-1.4.18-x86_64.msi", data);
        let keys = [("fl-2026", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")];
        assert!(verify_update_manifest_with_keys(&keys, &envelope, "1.4.18", &path).is_err());
        cleanup(&path);
    }

    #[test]
    fn reject_wrong_version() {
        let data = b"MSI factice";
        let path = test_file("version", data);
        let (key, envelope) = signed_envelope("fl-test", "1.4.17", "flowline-1.4.17-x86_64.msi", data);
        let keys = [(&key.0[..], &key.1[..])];
        assert!(verify_update_manifest_with_keys(&keys, &envelope, "1.4.18", &path).is_err());
        cleanup(&path);
    }

    #[test]
    fn reject_size_mismatch() {
        let data = b"MSI factice";
        let path = test_file("size", data);
        let (key, envelope) =
            signed_envelope("fl-test", "1.4.18", "flowline-1.4.18-x86_64.msi", b"autre contenu");
        let keys = [(&key.0[..], &key.1[..])];
        assert!(verify_update_manifest_with_keys(&keys, &envelope, "1.4.18", &path).is_err());
        cleanup(&path);
    }

    #[test]
    fn reject_swapped_file_same_size() {
        // Même taille, contenu différent => le SHA-256 doit refuser.
        let data = b"MSI factice 1";
        let path = test_file("swap", data);
        let (key, envelope) = signed_envelope(
            "fl-test",
            "1.4.18",
            "flowline-1.4.18-x86_64.msi",
            b"MSI factice 2",
        );
        let keys = [(&key.0[..], &key.1[..])];
        assert!(verify_update_manifest_with_keys(&keys, &envelope, "1.4.18", &path).is_err());
        cleanup(&path);
    }
}