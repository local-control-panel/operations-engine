//! Bounded, proxy-free access to a Meilisearch container's private address.
//! The master key is attached in memory as an HTTP header and is never part of
//! a subprocess argument or persisted request state.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{meilisearch_upgrade::SearchProbe, process::CancellationToken};

#[derive(Debug)]
pub enum Error {
    PublicAddress,
    Request(ureq::Error),
    Decode(ureq::Error),
    InvalidStats,
    DumpTaskFailed,
    DumpTaskTimedOut,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    pub pkg_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnqueuedTask {
    pub task_uid: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Task {
    pub uid: u64,
    pub status: String,
    #[serde(default)]
    pub error: Option<serde_json::Value>,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub estimated_total_hits: u64,
    pub hits: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ValidationSnapshot {
    pub index_document_counts: BTreeMap<String, u64>,
    pub searches: Vec<SearchResult>,
}

pub struct Client {
    agent: ureq::Agent,
    base_url: String,
    authorization: String,
}

impl Client {
    pub fn for_container(address: SocketAddr, master_key: &str) -> Result<Self, Error> {
        if !is_container_address(address.ip()) {
            return Err(Error::PublicAddress);
        }
        let config = ureq::config::Config::builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_recv_body(Some(Duration::from_secs(20)))
            .proxy(None)
            .https_only(false)
            .build();
        Ok(Self {
            agent: ureq::Agent::new_with_config(config),
            base_url: format!("http://{address}"),
            authorization: format!("Bearer {master_key}"),
        })
    }

    pub fn version(&self) -> Result<Version, Error> {
        self.get("/version")
    }

    pub fn stats(&self) -> Result<serde_json::Value, Error> {
        self.get("/stats")
    }

    pub fn task(&self, uid: u64) -> Result<Task, Error> {
        self.get(&format!("/tasks/{uid}"))
    }

    pub fn create_dump(&self) -> Result<EnqueuedTask, Error> {
        let mut response = self
            .agent
            .post(format!("{}/dumps", self.base_url))
            .header("Authorization", &self.authorization)
            .send_empty()
            .map_err(Error::Request)?;
        response.body_mut().read_json().map_err(Error::Decode)
    }

    pub fn search(&self, index_uid: &str, query: &str) -> Result<SearchResult, Error> {
        let body = serde_json::json!({ "q": query });
        let mut response = self
            .agent
            .post(format!("{}/indexes/{index_uid}/search", self.base_url))
            .header("Authorization", &self.authorization)
            .send_json(body)
            .map_err(Error::Request)?;
        response.body_mut().read_json().map_err(Error::Decode)
    }

    pub fn capture_validation(&self, probes: &[SearchProbe]) -> Result<ValidationSnapshot, Error> {
        let stats = self.stats()?;
        let indexes = stats
            .get("indexes")
            .and_then(serde_json::Value::as_object)
            .ok_or(Error::InvalidStats)?;
        let mut index_document_counts = BTreeMap::new();
        for (uid, stats) in indexes {
            let count = stats
                .get("numberOfDocuments")
                .and_then(serde_json::Value::as_u64)
                .ok_or(Error::InvalidStats)?;
            index_document_counts.insert(uid.clone(), count);
        }
        let searches = probes
            .iter()
            .map(|probe| self.search(&probe.index_uid, &probe.query))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ValidationSnapshot {
            index_document_counts,
            searches,
        })
    }

    pub fn create_dump_and_wait(
        &self,
        cancellation: &CancellationToken,
        timeout: Duration,
    ) -> Result<String, Error> {
        let uid = self.create_dump()?.task_uid;
        let started = Instant::now();
        loop {
            if cancellation.is_cancelled() {
                return Err(Error::Cancelled);
            }
            if started.elapsed() >= timeout {
                return Err(Error::DumpTaskTimedOut);
            }
            let task = self.task(uid)?;
            match task.status.as_str() {
                "succeeded" => {
                    return task
                        .details
                        .as_ref()
                        .and_then(|details| details.get("dumpUid"))
                        .and_then(serde_json::Value::as_str)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .ok_or(Error::DumpTaskFailed);
                }
                "failed" | "canceled" => return Err(Error::DumpTaskFailed),
                "enqueued" | "processing" => thread::sleep(Duration::from_millis(250)),
                _ => return Err(Error::DumpTaskFailed),
            }
        }
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let mut response = self
            .agent
            .get(format!("{}{path}", self.base_url))
            .header("Authorization", &self.authorization)
            .call()
            .map_err(Error::Request)?;
        response.body_mut().read_json().map_err(Error::Decode)
    }
}

fn is_container_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use super::*;

    #[test]
    fn refuses_public_network_destinations() {
        assert!(matches!(
            Client::for_container("8.8.8.8:7700".parse().unwrap(), "secret"),
            Err(Error::PublicAddress)
        ));
    }

    #[test]
    fn sends_the_key_only_as_an_authorization_header_and_decodes_version() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /version HTTP/1.1"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-secret")
            );
            let body = r#"{"pkgVersion":"1.53.2"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });

        let client = Client::for_container(address, "test-secret").unwrap();
        assert_eq!(client.version().unwrap().pkg_version, "1.53.2");
        server.join().unwrap();
    }

    #[test]
    fn validation_snapshot_ignores_dynamic_stats_fields() {
        let stats = serde_json::json!({
            "databaseSize": 999,
            "lastUpdate": "changes on every import",
            "indexes": {
                "products": { "numberOfDocuments": 12, "isIndexing": false },
                "pages": { "numberOfDocuments": 4, "fieldDistribution": { "title": 4 } }
            }
        });
        let indexes = stats["indexes"].as_object().unwrap();
        let counts = indexes
            .iter()
            .map(|(uid, value)| (uid.clone(), value["numberOfDocuments"].as_u64().unwrap()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(counts.get("products"), Some(&12));
        assert_eq!(counts.get("pages"), Some(&4));
        assert!(
            !serde_json::to_string(&counts)
                .unwrap()
                .contains("lastUpdate")
        );
    }
}
