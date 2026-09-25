use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = format!("{}/protos", std::env::var("OUT_DIR").unwrap());

    std::fs::create_dir_all(&out_dir).unwrap();

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(out_dir)
        .inputs(["protos/rendezvous.proto", "protos/message.proto"])
        .include("protos")
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run()
        .expect("Codegen failed.");

    // FlowLINE white-label : serveurs de rendez-vous + clé publique configurables
    // par variables d'environnement au build, pour déployer un client vers n'importe
    // quelle infra sans éditer le code. Le build.rs génère un fichier inclus par
    // config.rs (`$OUT_DIR/flowline_config.rs`). Défauts = infra falcon.
    //
    // NB: `cargo:rerun-if-env-changed` déclare la dépendance → recompile quand la
    // variable change (contrairement à `option_env!` que Cargo ne re-détecte pas).
    let servers = env::var("RUSTDESK_RENDEZVOUS_SERVERS")
        .unwrap_or_else(|_| "falcon.my-vth.ch".to_string());
    let pub_key = env::var("RUSTDESK_RS_PUB_KEY")
        .unwrap_or_else(|_| "y7HFkRp6dnePO7+ehiUSpbhUIqAwnRYDdquULvqJQXg=".to_string());
    // API compte FlowLINE (0051) : URL https obligatoire (TLS via NPM). Une
    // valeur vide ou http:// fait échouer le build — plus aucun fallback http
    // clair possible (l'ancienne dérivation `http://<rendezvous>:21114` est
    // supprimée côté client).
    let api_server = env::var("FLOWLINE_API_SERVER")
        .unwrap_or_else(|_| "https://api-falcon.my-vth.ch".to_string());
    if !api_server.starts_with("https://") {
        panic!(
            "FLOWLINE_API_SERVER doit etre une URL https explicite (recu: {:?})",
            api_server
        );
    }
    // Serveur de version (contrat d'update RustDesk) : le client POSTe ici un
    // petit payload et reçoit l'URL du tag de la dernière version. Côté FlowLINE,
    // c'est l'endpoint /api/update/version/latest de l'API compte.
    let version_url = env::var("FLOWLINE_VERSION_URL")
        .unwrap_or_else(|_| "https://api-falcon.my-vth.ch/api/update/version/latest".to_string());
    // N-05 (audit 21/09) : meme exigence https que FLOWLINE_API_SERVER — le
    // client POSTe des infos de version (et recevra a terme l'URL de MAJ) vers
    // cet endpoint ; une URL http en clair serait une surface MITM.
    if !version_url.starts_with("https://") {
        panic!(
            "FLOWLINE_VERSION_URL doit etre une URL https explicite (recu: {:?})",
            version_url
        );
    }
    // Forcer toutes les sessions par le relay (désactive le punch UDP) : garantit
    // la mesure relay (0001) et que le service relay payé est bien utilisé (0006).
    let force_relay = env::var("FLOWLINE_FORCE_RELAY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    // Masquer des réglages sensibles côté technicien (0054/0055) : onglet Network,
    // 2FA, Change ID. Compilé en dur → non modifiable côté client. `=0` pour un
    // build sans restriction (debug).
    let restrict_settings = env::var("FLOWLINE_RESTRICT_SETTINGS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    // Signature des mises a jour (0050) : ring de cles publiques Ed25519
    // embarquees, format `key_id:base64[,key_id:base64]`. La cle privee reste
    // hors ligne (pass + playbook de release) ; `key_id` permet la rotation en
    // embarquant l'ancienne et la nouvelle cle dans le meme build. Une cle
    // absente du ring => mise a jour refusee (fail closed).
    let update_keys = env::var("FLOWLINE_UPDATE_KEYS")
        .unwrap_or_else(|_| "fl-2026:REMPLACER_PAR_LA_CLE_PUBLIQUE".to_string());
    let update_keys_list = update_keys
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            let (id, key) = s
                .split_once(':')
                .unwrap_or_else(|| panic!("FLOWLINE_UPDATE_KEYS: entree sans ':' ({s:?})"));
            format!("    (\"{}\", \"{}\"),", id.trim(), key.trim())
        })
        .collect::<Vec<_>>()
        .join("\n");

    let dest = PathBuf::from(env::var("OUT_DIR").unwrap()).join("flowline_config.rs");
    let list = servers
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| format!("    \"{s}\","))
        .collect::<Vec<_>>()
        .join("\n");
    let force_relay = if force_relay { "true" } else { "false" };
    let restrict_settings = if restrict_settings { "true" } else { "false" };

    std::fs::write(
        &dest,
        format!(
            "pub const FLOWLINE_RENDEZVOUS_SERVERS: &[&str] = &[\n{list}\n];\n\
             pub const FLOWLINE_RS_PUB_KEY: &str = \"{pub_key}\";\n\
             pub const FLOWLINE_API_SERVER: &str = \"{api_server}\";\n\
             pub const FLOWLINE_VERSION_URL: &str = \"{version_url}\";\n\
             pub const FLOWLINE_FORCE_RELAY: bool = {force_relay};\n\
             pub const FLOWLINE_RESTRICT_SETTINGS: bool = {restrict_settings};\n\
             pub const FLOWLINE_UPDATE_KEYS: &[(&str, &str)] = &[\n{update_keys_list}\n];\n"
        ),
    )
    .expect("write flowline_config.rs");

    println!("cargo:rerun-if-env-changed=RUSTDESK_RENDEZVOUS_SERVERS");
    println!("cargo:rerun-if-env-changed=RUSTDESK_RS_PUB_KEY");
    println!("cargo:rerun-if-env-changed=FLOWLINE_API_SERVER");
    println!("cargo:rerun-if-env-changed=FLOWLINE_VERSION_URL");
    println!("cargo:rerun-if-env-changed=FLOWLINE_FORCE_RELAY");
    println!("cargo:rerun-if-env-changed=FLOWLINE_RESTRICT_SETTINGS");
    println!("cargo:rerun-if-env-changed=FLOWLINE_UPDATE_KEYS");
}
