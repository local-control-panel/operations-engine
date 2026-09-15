//! Production Docker/Compose driver for the controlled Meilisearch upgrade.

use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;

use crate::{
    meilisearch_upgrade::{
        TARGET_VERSION, UpgradeRequest,
        api::{self, Client, ValidationSnapshot},
        execute::{Baseline, Driver, ExportedDump, ImportedTarget},
    },
    process::{
        self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::{SiteRelativePath, TrustedRoot},
};

const API_PORT: u16 = 7700;
const DUMP_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const START_TIMEOUT: Duration = Duration::from_secs(10 * 60);

#[derive(Debug)]
pub enum Error {
    Process(process::ProcessRunError),
    Rejected(SubprocessDiagnostics),
    InvalidInspect,
    MissingContainer,
    MissingPrivateNetwork,
    MissingDataVolume,
    InvalidDumpUid,
    InvalidDump,
    Io(std::io::Error),
    Api(api::Error),
    ValidationMismatch,
    Cancelled,
}

impl From<api::Error> for Error {
    fn from(error: api::Error) -> Self {
        Self::Api(error)
    }
}

#[derive(Clone, Debug)]
struct Source {
    container_id: String,
    image: String,
    volume: String,
    network: String,
    address: SocketAddr,
}

#[derive(Clone, Debug)]
struct Candidate {
    container_name: String,
    volume: String,
    address: SocketAddr,
}

pub struct DockerDriver<'a> {
    docker_program: &'a str,
    stack_dir: &'a Path,
    state_root: &'a TrustedRoot,
    source: Option<Source>,
    candidate: Option<Candidate>,
}

impl<'a> DockerDriver<'a> {
    pub fn new(stack_dir: &'a Path, state_root: &'a TrustedRoot) -> Self {
        Self {
            docker_program: "docker",
            stack_dir,
            state_root,
            source: None,
            candidate: None,
        }
    }

    #[cfg(test)]
    fn with_docker(
        stack_dir: &'a Path,
        state_root: &'a TrustedRoot,
        docker_program: &'a str,
    ) -> Self {
        let mut driver = Self::new(stack_dir, state_root);
        driver.docker_program = docker_program;
        driver
    }

    fn compose(&self, args: &[&str], cancellation: &CancellationToken) -> Result<Vec<u8>, Error> {
        let mut argv = vec![
            "compose",
            "-p",
            "wcp",
            "--env-file",
            ".env",
            "-f",
            "stack/docker-compose.yml",
        ];
        argv.extend_from_slice(args);
        self.run(
            ProcessRequest::new(self.docker_program).args(argv),
            cancellation,
        )
    }

    fn docker<I, S>(&self, args: I, cancellation: &CancellationToken) -> Result<Vec<u8>, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.run(
            ProcessRequest::new(self.docker_program).args(args),
            cancellation,
        )
    }

    fn run(
        &self,
        request: ProcessRequest,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>, Error> {
        let limits = ProcessLimits {
            timeout: START_TIMEOUT,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 256 * 1024,
        };
        let output = process::run(&request.current_dir(self.stack_dir), &limits, cancellation)
            .map_err(Error::Process)?;
        if !matches!(
            output.termination,
            ProcessTermination::Exited { success: true, .. }
        ) {
            return Err(Error::Rejected(SubprocessDiagnostics::from_output(
                self.docker_program,
                &output,
            )));
        }
        Ok(output.stdout.bytes)
    }

    fn discover_service(&self, service: &str) -> Result<Source, Error> {
        let output = self.compose(
            &["--profile", "meilisearch", "ps", "-q", service],
            &CancellationToken::default(),
        )?;
        let container_id = std::str::from_utf8(&output)
            .map_err(|_| Error::InvalidInspect)?
            .trim()
            .to_owned();
        if container_id.is_empty()
            || !container_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-' || byte == b'_')
        {
            return Err(Error::MissingContainer);
        }
        let inspect = self.docker(
            ["inspect", container_id.as_str()],
            &CancellationToken::default(),
        )?;
        inspect_source(&inspect, container_id)
    }

    fn discover_source(&self, request: &UpgradeRequest) -> Result<Source, Error> {
        self.discover_service(request.service.as_str())
    }

    fn client(&self, source: &Source, key: &str) -> Result<Client, Error> {
        Client::for_container(source.address, key).map_err(Error::Api)
    }

    fn candidate_client(&self, key: &str) -> Result<Client, Error> {
        let candidate = self.candidate.as_ref().ok_or(Error::MissingContainer)?;
        Client::for_container(candidate.address, key).map_err(Error::Api)
    }

    fn wait_candidate(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<(), Error> {
        let started = Instant::now();
        loop {
            if cancellation.is_cancelled() {
                return Err(Error::Cancelled);
            }
            if started.elapsed() >= START_TIMEOUT {
                return Err(Error::InvalidInspect);
            }
            let container_name = self
                .candidate
                .as_ref()
                .ok_or(Error::MissingContainer)?
                .container_name
                .clone();
            if let Ok(inspect) = self.docker(
                ["inspect", container_name.as_str()],
                &CancellationToken::default(),
            ) {
                if let Ok(address) = inspect_address(&inspect, &container_name) {
                    self.candidate
                        .as_mut()
                        .expect("candidate remains present")
                        .address = address;
                    if let Ok(client) = Client::for_container(address, &request.master_key) {
                        if client
                            .version()
                            .is_ok_and(|version| version.pkg_version == TARGET_VERSION)
                        {
                            return Ok(());
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    fn wait_live_target(
        &self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<(), Error> {
        let started = Instant::now();
        loop {
            if cancellation.is_cancelled() {
                return Err(Error::Cancelled);
            }
            if started.elapsed() >= START_TIMEOUT {
                return Err(Error::InvalidInspect);
            }
            if let Ok(live) = self.discover_source(request) {
                if self
                    .client(&live, &request.master_key)
                    .and_then(|client| client.version().map_err(Error::Api))
                    .is_ok_and(|version| version.pkg_version == TARGET_VERSION)
                {
                    return Ok(());
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    fn env_path(&self) -> PathBuf {
        self.stack_dir.join(".env")
    }

    fn activate_pointers(&self, image: &str, volume: &str) -> Result<(), Error> {
        update_env_atomic(
            &self.env_path(),
            &[
                ("WCP_MEILISEARCH_IMAGE", image),
                ("WCP_MEILISEARCH_VOLUME", volume),
            ],
        )
        .map_err(Error::Io)
    }
}

impl crate::meilisearch_upgrade::cleanup::Driver for DockerDriver<'_> {
    type Error = Error;

    fn active_volume(&mut self) -> Result<String, Self::Error> {
        self.discover_service("meili-1").map(|source| source.volume)
    }

    fn remove_volume(&mut self, volume: &str) -> Result<(), Self::Error> {
        let filter = format!("name=^{volume}$");
        let existing = self.docker(
            ["volume", "ls", "--quiet", "--filter", filter.as_str()],
            &CancellationToken::default(),
        )?;
        if !std::str::from_utf8(&existing)
            .map_err(|_| Error::InvalidInspect)?
            .lines()
            .any(|name| name == volume)
        {
            return Ok(());
        }
        self.docker(["volume", "rm", volume], &CancellationToken::default())?;
        Ok(())
    }
}

impl Driver for DockerDriver<'_> {
    type Error = Error;

    fn capture_baseline(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<Baseline, Error> {
        if cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let source = self.discover_source(request)?;
        let client = self.client(&source, &request.master_key)?;
        let version = client.version()?.pkg_version;
        let snapshot = client.capture_validation(&request.search_probes)?;
        let source_volume = source.volume.clone();
        self.source = Some(source);
        Ok(Baseline {
            source_version: version,
            source_volume,
            validation_token: serde_json::to_string(&snapshot)
                .map_err(|_| Error::InvalidInspect)?,
        })
    }

    fn create_and_export_dump(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<ExportedDump, Error> {
        let source = self.source.as_ref().ok_or(Error::MissingContainer)?;
        let dump_uid = self
            .client(source, &request.master_key)?
            .create_dump_and_wait(cancellation, DUMP_TIMEOUT)?;
        if dump_uid.is_empty()
            || dump_uid.len() > 128
            || !dump_uid.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(Error::InvalidDumpUid);
        }
        let relative = SiteRelativePath::parse(format!(
            "meilisearch/{}/backups/{}/{}.dump",
            request.stack_name.as_str(),
            request.request_id,
            dump_uid
        ))
        .map_err(|_| Error::InvalidDumpUid)?;
        let destination = self.state_root.join(&relative);
        let parent = destination.parent().ok_or(Error::InvalidDump)?;
        fs::create_dir_all(parent).map_err(Error::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(Error::Io)?;
        }
        let remote = format!(
            "{}:/meili_data/dumps/{}.dump",
            source.container_id, dump_uid
        );
        self.docker(
            [
                "cp",
                remote.as_str(),
                destination.to_string_lossy().as_ref(),
            ],
            cancellation,
        )?;
        let metadata = fs::symlink_metadata(&destination).map_err(Error::Io)?;
        if !metadata.file_type().is_file() || metadata.len() == 0 {
            return Err(Error::InvalidDump);
        }
        Ok(ExportedDump {
            backup_id: dump_uid,
            byte_len: metadata.len(),
        })
    }

    fn stop_source(
        &mut self,
        request: &UpgradeRequest,
        cancellation: &CancellationToken,
    ) -> Result<(), Error> {
        self.compose(
            &["--profile", "meilisearch", "stop", request.service.as_str()],
            cancellation,
        )?;
        Ok(())
    }

    fn import_target(
        &mut self,
        request: &UpgradeRequest,
        dump: &ExportedDump,
        cancellation: &CancellationToken,
    ) -> Result<ImportedTarget, Error> {
        let source = self.source.as_ref().ok_or(Error::MissingContainer)?;
        let suffix = request.request_id.to_string().replace('-', "");
        let suffix = &suffix[..12];
        let volume = format!(
            "wcp_meilisearch_{}_{}",
            TARGET_VERSION.replace('.', "_"),
            suffix
        );
        let container_name = format!("wcp-meilisearch-upgrade-{suffix}");
        let dump_path = self.state_root.join(
            &SiteRelativePath::parse(format!(
                "meilisearch/{}/backups/{}/{}.dump",
                request.stack_name.as_str(),
                request.request_id,
                dump.backup_id
            ))
            .map_err(|_| Error::InvalidDump)?,
        );
        self.docker(["volume", "create", volume.as_str()], cancellation)?;
        let mount = format!("{}:/upgrade.dump:ro", dump_path.to_string_lossy());
        let volume_mount = format!("{volume}:/meili_data");
        let request_to_run = ProcessRequest::new(self.docker_program)
            .args([
                "run",
                "-d",
                "--name",
                container_name.as_str(),
                "--network",
                source.network.as_str(),
                "--security-opt",
                "no-new-privileges:true",
                "-e",
                "MEILI_MASTER_KEY",
                "-e",
                "MEILI_ENV=production",
                "-v",
                volume_mount.as_str(),
                "-v",
                mount.as_str(),
                request.target_image,
                "/bin/meilisearch",
                "--db-path",
                "/meili_data",
                "--import-dump",
                "/upgrade.dump",
            ])
            .env("MEILI_MASTER_KEY", &request.master_key);
        self.run(request_to_run, cancellation)?;
        self.candidate = Some(Candidate {
            container_name,
            volume: volume.clone(),
            address: "127.0.0.1:7700".parse().expect("static address"),
        });
        self.wait_candidate(request, cancellation)?;
        Ok(ImportedTarget { volume })
    }

    fn validate_target(
        &mut self,
        request: &UpgradeRequest,
        baseline: &Baseline,
        target: &ImportedTarget,
        _cancellation: &CancellationToken,
    ) -> Result<(), Error> {
        if self.candidate.as_ref().map(|value| &value.volume) != Some(&target.volume) {
            return Err(Error::MissingDataVolume);
        }
        let actual = self
            .candidate_client(&request.master_key)?
            .capture_validation(&request.search_probes)?;
        let expected: ValidationSnapshot =
            serde_json::from_str(&baseline.validation_token).map_err(|_| Error::InvalidInspect)?;
        if actual != expected {
            return Err(Error::ValidationMismatch);
        }
        Ok(())
    }

    fn cutover(
        &mut self,
        request: &UpgradeRequest,
        target: &ImportedTarget,
        cancellation: &CancellationToken,
    ) -> Result<(), Error> {
        let candidate = self.candidate.as_ref().ok_or(Error::MissingContainer)?;
        self.docker(
            ["rm", "-f", candidate.container_name.as_str()],
            cancellation,
        )?;
        self.activate_pointers(request.target_image, &target.volume)?;
        self.compose(
            &[
                "--profile",
                "meilisearch",
                "up",
                "-d",
                request.service.as_str(),
            ],
            cancellation,
        )?;
        self.wait_live_target(request, cancellation)
    }

    fn rollback_source(&mut self, request: &UpgradeRequest) -> Result<(), Error> {
        if let Some(candidate) = self.candidate.as_ref() {
            let _ = self.docker(
                ["rm", "-f", candidate.container_name.as_str()],
                &CancellationToken::default(),
            );
        }
        let source = self.source.as_ref().ok_or(Error::MissingContainer)?;
        self.activate_pointers(&source.image, &source.volume)?;
        self.compose(
            &[
                "--profile",
                "meilisearch",
                "up",
                "-d",
                request.service.as_str(),
            ],
            &CancellationToken::default(),
        )?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Inspect {
    config: InspectConfig,
    network_settings: NetworkSettings,
    mounts: Vec<Mount>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InspectConfig {
    image: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkSettings {
    networks: std::collections::BTreeMap<String, Network>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Network {
    #[serde(rename = "IPAddress")]
    ip_address: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Mount {
    r#type: String,
    name: Option<String>,
    destination: String,
}

fn inspect_source(json: &[u8], container_id: String) -> Result<Source, Error> {
    let mut values: Vec<Inspect> =
        serde_json::from_slice(json).map_err(|_| Error::InvalidInspect)?;
    if values.len() != 1 {
        return Err(Error::InvalidInspect);
    }
    let inspect = values.remove(0);
    let (network, address) = private_network(&inspect.network_settings.networks)?;
    let volume = inspect
        .mounts
        .iter()
        .find(|mount| mount.r#type == "volume" && mount.destination == "/meili_data")
        .and_then(|mount| mount.name.clone())
        .ok_or(Error::MissingDataVolume)?;
    Ok(Source {
        container_id,
        image: inspect.config.image,
        volume,
        network,
        address,
    })
}

fn inspect_address(json: &[u8], _container: &str) -> Result<SocketAddr, Error> {
    let mut values: Vec<Inspect> =
        serde_json::from_slice(json).map_err(|_| Error::InvalidInspect)?;
    if values.len() != 1 {
        return Err(Error::InvalidInspect);
    }
    private_network(&values.remove(0).network_settings.networks).map(|(_, address)| address)
}

fn private_network(
    networks: &std::collections::BTreeMap<String, Network>,
) -> Result<(String, SocketAddr), Error> {
    for (name, network) in networks {
        let Ok(ip) = network.ip_address.parse::<IpAddr>() else {
            continue;
        };
        let private = match ip {
            IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
            IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00,
        };
        if private && (name == "wcp_backend" || name.ends_with("_backend")) {
            return Ok((name.clone(), SocketAddr::new(ip, API_PORT)));
        }
    }
    Err(Error::MissingPrivateNetwork)
}

fn update_env_atomic(path: &Path, updates: &[(&str, &str)]) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::other("compose env is not a regular file"));
    }
    let original = fs::read_to_string(path)?;
    let mut lines = original.lines().map(str::to_owned).collect::<Vec<_>>();
    for (key, value) in updates {
        if value.contains(['\r', '\n', '\0']) {
            return Err(std::io::Error::other("invalid env pointer"));
        }
        let prefix = format!("{key}=");
        if let Some(line) = lines.iter_mut().find(|line| line.starts_with(&prefix)) {
            *line = format!("{key}={value}");
        } else {
            lines.push(format!("{key}={value}"));
        }
    }
    let content = format!("{}\n", lines.join("\n"));
    let temporary = path.with_extension("env.meilisearch.tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        let mut file = options.open(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }
    fs::set_permissions(&temporary, metadata.permissions())?;
    fs::rename(temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_selects_only_the_backend_network_and_named_data_volume() {
        let json = br#"[{"Config":{"Image":"old@sha256:abc"},"NetworkSettings":{"Networks":{"wcp_edge":{"IPAddress":"172.20.0.2"},"wcp_backend":{"IPAddress":"172.21.0.4"}}},"Mounts":[{"Type":"volume","Name":"wcp_meilisearch_data","Destination":"/meili_data"}]}]"#;
        let source = inspect_source(json, "container123".into()).unwrap();
        assert_eq!(source.network, "wcp_backend");
        assert_eq!(source.address, "172.21.0.4:7700".parse().unwrap());
        assert_eq!(source.volume, "wcp_meilisearch_data");
    }

    #[test]
    fn env_pointer_update_preserves_secrets_and_replaces_only_selected_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        fs::write(
            &path,
            "MEILISEARCH_MASTER_KEY=keep-secret\nWCP_MEILISEARCH_IMAGE=old\n",
        )
        .unwrap();
        update_env_atomic(
            &path,
            &[
                ("WCP_MEILISEARCH_IMAGE", "new@sha256:123"),
                ("WCP_MEILISEARCH_VOLUME", "new-volume"),
            ],
        )
        .unwrap();
        let actual = fs::read_to_string(path).unwrap();
        assert!(actual.contains("MEILISEARCH_MASTER_KEY=keep-secret"));
        assert!(actual.contains("WCP_MEILISEARCH_IMAGE=new@sha256:123"));
        assert!(actual.contains("WCP_MEILISEARCH_VOLUME=new-volume"));
        assert!(!dir.path().join(".env.env.meilisearch.tmp").exists());
    }

    #[test]
    fn public_or_edge_only_inspect_is_rejected() {
        let json = br#"[{"Config":{"Image":"old"},"NetworkSettings":{"Networks":{"wcp_edge":{"IPAddress":"8.8.8.8"}}},"Mounts":[]}]"#;
        assert!(matches!(
            inspect_source(json, "container123".into()),
            Err(Error::MissingPrivateNetwork)
        ));
    }

    #[test]
    fn test_constructor_keeps_dependencies_explicit() {
        let stack = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let trusted = TrustedRoot::parse(state.path()).unwrap();
        let driver = DockerDriver::with_docker(stack.path(), &trusted, "/fake/docker");
        assert_eq!(driver.docker_program, "/fake/docker");
    }
}
