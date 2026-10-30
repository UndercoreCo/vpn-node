//! MIT-licensed node authorization bridge. No customer data or traffic logging.
use super::{Authenticator, Source, Status};
use crate::log_utils;
use ring::digest;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

pub trait Session: Send {
    fn revoked(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

struct Entry {
    username: String,
    expires: Mutex<(u64, Instant)>,
    cancelled: watch::Sender<bool>,
    active: AtomicUsize,
}
impl Entry {
    fn valid(&self, now: u64) -> bool {
        let expiry = self.expires.lock().unwrap();
        !*self.cancelled.borrow() && now < expiry.0 && Instant::now() < expiry.1
    }
}
struct Permit {
    entry: Arc<Entry>,
    changed: watch::Receiver<bool>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.entry.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Session for Permit {
    fn revoked(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            loop {
                if *self.changed.borrow_and_update() || !self.entry.valid(wall_ms()) {
                    return;
                }
                tokio::select! {
                    result = self.changed.changed() => { if result.is_err() { return; } },
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                }
            }
        })
    }
}
struct Denied;
impl Session for Denied {
    fn revoked(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Client {
    username: String,
    credential: String,
    expires_ms: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    generation: u64,
    clients: Vec<Client>,
}
#[derive(Serialize)]
struct Acknowledgement {
    generation: u64,
    applied: bool,
    boot: String,
    wall_ms: u64,
}
#[derive(Default)]
struct State {
    generation: u64,
    loaded: bool,
    entries: HashMap<String, Arc<Entry>>,
    retired: Vec<Arc<Entry>>,
}
impl State {
    fn deny_all(&mut self) {
        self.loaded = false;
        for (_, entry) in self.entries.drain() {
            entry.cancelled.send_replace(true);
            self.retired.push(entry);
        }
    }
    fn apply(&mut self, snapshot: Snapshot, now: u64) -> Result<(), ()> {
        if snapshot.generation == 0 || snapshot.clients.len() > 10000 {
            return Err(());
        }
        let mut names = HashSet::new();
        let mut hashes = HashSet::new();
        for c in &snapshot.clients {
            if c.username.len() != 38
                || !c.username.starts_with("ttapi_")
                || !c.username[6..].bytes().all(|b| b.is_ascii_hexdigit())
                || c.credential.len() != 64
                || !c.credential.bytes().all(|b| b.is_ascii_hexdigit())
                || !names.insert(c.username.clone())
                || !hashes.insert(c.credential.clone())
                || c.expires_ms > 4102444800000
            {
                return Err(());
            }
        }
        if snapshot.generation < self.generation {
            return Err(());
        }
        if snapshot.generation == self.generation && self.loaded {
            return Ok(());
        }
        let mut previous = std::mem::take(&mut self.entries);
        for c in snapshot.clients {
            if c.expires_ms <= now {
                continue;
            }
            let deadline = Instant::now() + Duration::from_millis(c.expires_ms - now);
            let entry = match previous.remove(&c.credential) {
                Some(entry) if entry.valid(now) && entry.username == c.username => {
                    *entry.expires.lock().unwrap() = (c.expires_ms, deadline);
                    entry
                }
                old => {
                    if let Some(old) = old {
                        old.cancelled.send_replace(true);
                        self.retired.push(old);
                    }
                    Arc::new(Entry {
                        username: c.username,
                        expires: Mutex::new((c.expires_ms, deadline)),
                        cancelled: watch::channel(false).0,
                        active: AtomicUsize::new(0),
                    })
                }
            };
            self.entries.insert(c.credential, entry);
        }
        for (_, entry) in previous {
            entry.cancelled.send_replace(true);
            self.retired.push(entry);
        }
        self.generation = snapshot.generation;
        self.loaded = true;
        Ok(())
    }
    fn expire(&mut self, now: u64) {
        for entry in self.entries.values() {
            if !entry.valid(now) {
                entry.cancelled.send_replace(true);
            }
        }
        self.retired
            .retain(|entry| entry.active.load(Ordering::SeqCst) != 0);
    }
}

pub struct ManagedAuthenticator {
    state: Arc<Mutex<State>>,
}
fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn fingerprint(source: &Source<'_>) -> String {
    let value = match source {
        Source::ProxyBasic(v) | Source::Sni(v) => v.as_bytes(),
    };
    hex::encode(digest::digest(&digest::SHA256, value))
}
impl ManagedAuthenticator {
    pub fn start(snapshot: PathBuf, ack: PathBuf) -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let worker = state.clone();
        std::thread::spawn(move || {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let boot = format!("{:032x}", rand::random::<u128>());
            let mut floor = wall_ms();
            if let Ok(bytes) = std::fs::read(&ack) {
                if let Ok(old) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    floor = floor.max(old["wall_ms"].as_u64().unwrap_or(floor));
                    worker.lock().unwrap().generation = old["generation"].as_u64().unwrap_or(0);
                }
            }
            loop {
                let now = wall_ms();
                let valid_clock = now.saturating_add(2000) >= floor;
                floor = floor.max(now);
                let incoming = std::fs::metadata(&snapshot)
                    .ok()
                    .filter(|m| m.is_file() && m.len() <= 4 * 1024 * 1024)
                    .and_then(|_| std::fs::read(&snapshot).ok())
                    .and_then(|bytes| serde_json::from_slice::<Snapshot>(&bytes).ok());
                let status = {
                    let mut state = worker.lock().unwrap();
                    let applied = valid_clock
                        && incoming
                            .map(|s| state.apply(s, now).is_ok())
                            .unwrap_or(false);
                    if !applied {
                        state.deny_all();
                    }
                    state.expire(now);
                    Acknowledgement {
                        generation: state.generation,
                        applied: applied && state.retired.is_empty(),
                        boot: boot.clone(),
                        wall_ms: floor,
                    }
                };
                // A private parent directory is required. Never log file contents/errors.
                let temporary = ack.with_extension("next");
                let written = (|| -> std::io::Result<()> {
                    let bytes = serde_json::to_vec(&status)?;
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(&temporary)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    std::fs::rename(&temporary, &ack)
                })();
                if written.is_err() {
                    worker.lock().unwrap().deny_all();
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Self { state }
    }
}
impl Authenticator for ManagedAuthenticator {
    fn authenticate(&self, source: &Source<'_>, _: &log_utils::IdChain<u64>) -> Status {
        let state = self.state.lock().unwrap();
        if state
            .entries
            .get(&fingerprint(source))
            .map(|e| e.valid(wall_ms()))
            .unwrap_or(false)
        {
            Status::Pass
        } else {
            Status::Reject
        }
    }
    fn session(&self, source: &Source<'_>) -> Option<Box<dyn Session>> {
        let state = self.state.lock().unwrap();
        match state
            .entries
            .get(&fingerprint(source))
            .filter(|e| e.valid(wall_ms()))
        {
            Some(entry) => {
                entry.active.fetch_add(1, Ordering::SeqCst);
                Some(Box::new(Permit {
                    entry: entry.clone(),
                    changed: entry.cancelled.subscribe(),
                }))
            }
            None => Some(Box::new(Denied)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn client(id: char, expiry: u64) -> Client {
        Client {
            username: format!("ttapi_{}", id.to_string().repeat(32)),
            credential: id.to_string().repeat(64),
            expires_ms: expiry,
        }
    }
    #[tokio::test]
    async fn revoke_waits_for_forwarding_guard_and_preserves_other_client() {
        let now = wall_ms();
        let mut state = State::default();
        state
            .apply(
                Snapshot {
                    generation: 1,
                    clients: vec![client('a', now + 10000), client('b', now + 10000)],
                },
                now,
            )
            .unwrap();
        let entry = state.entries[&"a".repeat(64)].clone();
        entry.active.fetch_add(1, Ordering::SeqCst);
        let mut permit = Permit {
            entry: entry.clone(),
            changed: entry.cancelled.subscribe(),
        };
        state
            .apply(
                Snapshot {
                    generation: 2,
                    clients: vec![client('b', now + 10000)],
                },
                now,
            )
            .unwrap();
        state.expire(now);
        assert!(!state.retired.is_empty());
        tokio::time::timeout(Duration::from_millis(100), permit.revoked())
            .await
            .unwrap();
        assert!(state.entries[&"b".repeat(64)].valid(now));
        drop(permit);
        state.expire(now);
        assert!(state.retired.is_empty());
    }
    #[test]
    fn expiry_and_rotation_cancel_old_credentials() {
        let now = wall_ms();
        let mut state = State::default();
        state
            .apply(
                Snapshot {
                    generation: 1,
                    clients: vec![client('a', now + 1000)],
                },
                now,
            )
            .unwrap();
        let old = state.entries[&"a".repeat(64)].clone();
        state.expire(now + 1001);
        assert!(*old.cancelled.borrow());
        state
            .apply(
                Snapshot {
                    generation: 2,
                    clients: vec![client('b', now + 2000)],
                },
                now + 1001,
            )
            .unwrap();
        assert!(!state.entries.contains_key(&"a".repeat(64)));
        assert!(state.entries[&"b".repeat(64)].valid(now + 1001));
    }
    #[tokio::test]
    async fn session_expires_without_snapshot_worker() {
        let now = wall_ms();
        let mut state = State::default();
        state
            .apply(
                Snapshot {
                    generation: 1,
                    clients: vec![client('a', now + 80)],
                },
                now,
            )
            .unwrap();
        let entry = state.entries[&"a".repeat(64)].clone();
        entry.active.fetch_add(1, Ordering::SeqCst);
        let mut permit = Permit {
            changed: entry.cancelled.subscribe(),
            entry,
        };
        tokio::time::timeout(Duration::from_secs(1), permit.revoked())
            .await
            .unwrap();
    }
    #[test]
    fn rollback_is_rejected_even_after_invalid_snapshot() {
        let now = wall_ms();
        let mut state = State::default();
        state
            .apply(
                Snapshot {
                    generation: 5,
                    clients: vec![client('a', now + 1000)],
                },
                now,
            )
            .unwrap();
        state.deny_all();
        assert!(state
            .apply(
                Snapshot {
                    generation: 4,
                    clients: vec![client('b', now + 1000)]
                },
                now
            )
            .is_err());
        assert!(state.entries.is_empty());
        state
            .apply(
                Snapshot {
                    generation: 5,
                    clients: vec![client('a', now + 1000)],
                },
                now,
            )
            .unwrap();
        assert!(state.loaded);
    }
}
