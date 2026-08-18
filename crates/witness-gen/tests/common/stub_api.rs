//! An API that can be taken away and given back.
//!
//! Enough of an HTTP server to record what the daemon posted and to stop
//! answering on command, which is the only interesting thing an API can do to a
//! daemon that must not depend on it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// One request the stub API received.
#[derive(Clone, Debug)]
pub struct Received {
    pub path: String,
    pub authorization: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Received {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("stub received JSON")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// An API that can be taken away and given back.
#[derive(Clone)]
pub struct StubApi {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
    up: Arc<Mutex<bool>>,
}

impl StubApi {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let stub = Self {
            addr: listener.local_addr().expect("addr"),
            received: Arc::new(Mutex::new(Vec::new())),
            up: Arc::new(Mutex::new(true)),
        };
        let serving = stub.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let serving = serving.clone();
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 8192];
                    // Read until the headers are complete, then until the body is.
                    let (head_end, length) = loop {
                        let read = match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buffer.extend_from_slice(&chunk[..read]);
                        if let Some(at) = find(&buffer, b"\r\n\r\n") {
                            break (at + 4, content_length(&buffer[..at]));
                        }
                    };
                    while buffer.len() < head_end + length {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                        }
                    }

                    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
                    let mut lines = head.lines();
                    let path = lines
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or_default()
                        .to_string();
                    let headers: Vec<(String, String)> = lines
                        .filter_map(|line| line.split_once(": "))
                        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
                        .collect();

                    let up = *serving.up.lock().unwrap();
                    if up {
                        serving.received.lock().unwrap().push(Received {
                            path,
                            authorization: headers
                                .iter()
                                .find(|(k, _)| k == "authorization")
                                .map(|(_, v)| v.clone())
                                .unwrap_or_default(),
                            headers,
                            body: buffer[head_end..head_end + length].to_vec(),
                        });
                    }
                    let status = if up {
                        "200 OK"
                    } else {
                        "503 Service Unavailable"
                    };
                    let _ = socket
                        .write_all(
                            format!(
                                "HTTP/1.1 {status}\r\ncontent-length: 15\r\n\
                                 content-type: application/json\r\n\r\n{{\"ok\":{up}}}     "
                            )
                            .as_bytes(),
                        )
                        .await;
                });
            }
        });
        stub
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn take_down(&self) {
        *self.up.lock().unwrap() = false;
    }

    pub fn bring_up(&self) {
        *self.up.lock().unwrap() = true;
    }

    pub fn requests(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    /// Every event the stub has been told about, in arrival order.
    pub fn events(&self) -> Vec<Value> {
        self.requests()
            .iter()
            .filter(|r| r.path.ends_with("/v1/ingest"))
            .flat_map(|r| {
                r.json()["events"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
            })
            .collect()
    }

    pub async fn wait_for(&self, predicate: impl Fn(&Self) -> bool) -> bool {
        for _ in 0..200 {
            if predicate(self) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}
