#!/usr/bin/env python3
"""Apply a small reviewed bridge to the pinned upstream; never overwrite dirty sources."""

from pathlib import Path
import argparse
import subprocess
import shutil

REVISION = "fab5b8353a19332f935fa30869307d37d4a898d1"
ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("source", type=Path)
args = parser.parse_args()
source = args.source.resolve()
if (
    subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    != REVISION
):
    raise SystemExit("Unexpected upstream revision")
if subprocess.check_output(
    ["git", "-C", str(source), "status", "--porcelain"], text=True
).strip():
    raise SystemExit("Upstream checkout must be clean")
path = source / "lib/src/authentication/mod.rs"
s = path.read_text().replace(
    "pub mod registry_based;", "pub mod registry_based;\npub mod managed;"
)
s = s.replace(
    "pub trait Authenticator: Send + Sync {",
    """pub trait Authenticator: Send + Sync {
    /// Optional session permit. Dropping its forwarding future must release the permit.
    fn session(&self, _source: &Source<'_>) -> Option<Box<dyn managed::Session>> { None }
""",
)
path.write_text(s)
shutil.copy2(ROOT / "runtime/managed.rs", source / "lib/src/authentication/managed.rs")
path = source / "lib/src/tunnel.rs"
s = path.read_text()
start = s.index("                match request.promote_to_next_state() {")
end = s.index("\n            });", start)
body = s[start:end]
insert = (
    """                let mut permit = forwarder_auth.as_ref().and_then(|source|
                    context.authenticator.as_ref().and_then(|auth| auth.session(source)));
                let forwarding = async {
"""
    + body
    + """
                };
                if let Some(ref mut permit) = permit {
                    tokio::select! {
                        biased;
                        _ = permit.revoked() => {},
                        _ = forwarding => {},
                    }
                } else {
                    forwarding.await;
                }
"""
)
s = s[:start] + insert + s[end:]
path.write_text(s)
path = source / "endpoint/src/main.rs"
s = path.read_text().replace(
    "use trusttunnel::authentication::registry_based::RegistryBasedAuthenticator;",
    "use trusttunnel::authentication::managed::ManagedAuthenticator;",
)
start = s.index("    let authenticator: Option<Arc<dyn Authenticator>> =")
end = s.index("    let core =", start)
s = (
    s[:start]
    + """    let authenticator: Option<Arc<dyn Authenticator>> = Some(Arc::new(
        ManagedAuthenticator::start(
            std::env::var_os("VPN_NODE_SNAPSHOT").expect("Missing node snapshot path").into(),
            std::env::var_os("VPN_NODE_ACK").expect("Missing node acknowledgement path").into(),
        )
    ));
"""
    + s[end:]
)
path.write_text(s)
print("Prepared pinned TrustTunnel with node authorization/session bridge")
