//! A throwaway Sequentia chain for tests.
//!
//! Two `sequentiad` processes from the same binary: a Bitcoin-mode regtest node as the parent
//! chain, and a Sequentia custom chain (`elementsregtest`) whose block headers carry a Bitcoin
//! anchor taken from that parent, as on every live Sequentia chain. The Sequentia node has
//! Simplicity active from genesis, transparent defaults and the open fee market. Both nodes stop,
//! and their data directories are deleted, when the client is dropped.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use electrsd::bitcoind::bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::Value;

use smplx_sdk::provider::{ElementsRpc, SimplicityNetwork};

use super::RegtestConfig;
use super::error::RegtestError;

/// The node binary looked up on `PATH` when `node_bin` is not set.
pub const DEFAULT_SEQUENTIAD: &str = "sequentiad";

/// Overrides the directory the chain's data directories are created under.
pub const DATADIR_ENV_NAME: &str = "SIMPLEX_REGTEST_DIR";

/// The descriptor the parent chain mines to: a bare `OP_TRUE`.
const OP_TRUE_DESCRIPTOR: &str = "raw(51)";

/// The wallet the Sequentia node funds the signer from.
const WALLET: &str = "simplex";

/// The Sequentia node's chain: initial free coins at an `OP_TRUE` output of the genesis block,
/// transparent addresses, fees in any accepted asset, and Simplicity active from genesis. The
/// form `simplicity:-1:::` matters: `simplicity:0:::` activates only at height 384, and until then
/// a Simplicity output is spendable by anyone.
pub const CHAIN_ARGS: &[&str] = &[
    "-chain=elementsregtest",
    "-initialfreecoins=2100000000000000",
    "-con_default_blinded_addresses=0",
    "-blindedaddresses=0",
    "-validatepegin=0",
    "-con_parent_chain_signblockscript=51",
    "-con_any_asset_fees=1",
    "-evbparams=simplicity:-1:::",
    "-txindex=1",
    "-fallbackfee=0.0001",
    // Scripts checked on one thread: a refused block then names the script failure, rather
    // than the bare `block-validation-failed` that parallel checking reports.
    "-par=1",
];

/// One running `sequentiad`.
pub struct Daemon {
    child: Child,
    datadir: PathBuf,
    rpc_port: u16,
    client: Client,
}

impl Daemon {
    fn start(exe: &Path, datadir: PathBuf, rpc: &RpcSettings, args: &[String]) -> Result<Daemon, RegtestError> {
        let _ = std::fs::remove_dir_all(&datadir);
        std::fs::create_dir_all(&datadir)?;

        let rpc_port = rpc.port.unwrap_or_else(free_port);
        let mut all = vec![
            format!("-datadir={}", datadir.display()),
            format!("-rpcport={rpc_port}"),
            "-rpcbind=127.0.0.1".to_string(),
            "-rpcallowip=127.0.0.1".to_string(),
            format!("-port={}", free_port()),
            "-listen=0".to_string(),
            "-server".to_string(),
            "-printtoconsole=0".to_string(),
            format!("-rpcuser={}", rpc.user),
            format!("-rpcpassword={}", rpc.password),
        ];
        all.extend(args.iter().cloned());

        let child = Command::new(exe)
            .args(&all)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| RegtestError::NodeStart(format!("cannot start {}: {e}", exe.display())))?;

        let client = Client::new(
            &format!("http://127.0.0.1:{rpc_port}"),
            Auth::UserPass(rpc.user.clone(), rpc.password.clone()),
        )
        .map_err(|e| RegtestError::NodeStart(e.to_string()))?;

        let mut daemon = Daemon {
            child,
            datadir,
            rpc_port,
            client,
        };

        let start = Instant::now();

        loop {
            match daemon.client.get_block_count() {
                Ok(_) => return Ok(daemon),
                Err(e) => {
                    if let Ok(Some(status)) = daemon.child.try_wait() {
                        return Err(RegtestError::NodeStart(format!(
                            "sequentiad exited ({status}) before answering; its log is under {}",
                            daemon.datadir.display()
                        )));
                    }

                    if start.elapsed() > Duration::from_mins(1) {
                        return Err(RegtestError::NodeStart(format!(
                            "sequentiad did not answer within 60 s: {e}"
                        )));
                    }

                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }

    fn call(&self, method: &str, args: &[Value]) -> Result<Value, RegtestError> {
        self.client
            .call::<Value>(method, args)
            .map_err(|e| RegtestError::NodeCall(method.to_string(), e.to_string()))
    }

    fn stop(&mut self) {
        let _ = self.client.call::<Value>("stop", &[]);
        let start = Instant::now();

        while start.elapsed() < Duration::from_secs(30) {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct RpcSettings {
    port: Option<u16>,
    user: String,
    password: String,
}

/// A running Sequentia regtest chain: the Sequentia node and its Bitcoin parent.
pub struct SequentiaRegtestClient {
    node: Daemon,
    parent: Daemon,
    workdir: PathBuf,
    network: SimplicityNetwork,
    rpc_user: String,
    rpc_password: String,
    stopped: bool,
}

impl SequentiaRegtestClient {
    /// Starts the parent and the Sequentia node with the binary named in `config.node_bin`, or
    /// `sequentiad` on `PATH`, under a fresh work directory.
    ///
    /// # Errors
    /// Returns a `RegtestError` if either node fails to start or to answer.
    pub fn new(config: &RegtestConfig) -> Result<Self, RegtestError> {
        let exe = config
            .node_bin
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SEQUENTIAD));
        let workdir = Self::workdir()?;

        let rpc = RpcSettings {
            port: config.rpc_port,
            user: config.rpc_user.clone().unwrap_or_else(|| "simplex".to_string()),
            password: config.rpc_password.clone().unwrap_or_else(random_password),
        };
        let parent_rpc = RpcSettings {
            port: None,
            user: "parent".to_string(),
            password: random_password(),
        };

        let mut parent = Daemon::start(
            &exe,
            workdir.join("parent"),
            &parent_rpc,
            &["-chain=regtest".to_string()],
        )?;

        // Nothing is left running, nor any data left behind, when the chain fails to come up.
        let (node, network) = match Self::start_node(&exe, &workdir, &rpc, &parent, &parent_rpc) {
            Ok(started) => started,
            Err(e) => {
                parent.stop();
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(e);
            }
        };

        let client = Self {
            node,
            parent,
            workdir,
            network,
            rpc_user: rpc.user,
            rpc_password: rpc.password,
            stopped: false,
        };

        client.node.call("createwallet", &[WALLET.into()])?;

        Ok(client)
    }

    /// Starts the Sequentia node anchored to `parent`, and reads from the node which Sequentia
    /// network it runs. A binary that is not Sequentia's is refused here, whatever the
    /// configuration called it, and stopped.
    fn start_node(
        exe: &Path,
        workdir: &Path,
        rpc: &RpcSettings,
        parent: &Daemon,
        parent_rpc: &RpcSettings,
    ) -> Result<(Daemon, SimplicityNetwork), RegtestError> {
        // An anchor is a parent block: give the parent a few.
        parent.call("generatetodescriptor", &[10.into(), OP_TRUE_DESCRIPTOR.into()])?;
        let parent_genesis = parent.call("getblockhash", &[0.into()])?;

        let mut args: Vec<String> = vec![
            "-con_bitcoin_anchor=1".to_string(),
            "-validateanchor=1".to_string(),
            "-mainchainrpchost=127.0.0.1".to_string(),
            format!("-mainchainrpcport={}", parent.rpc_port),
            format!("-mainchainrpcuser={}", parent_rpc.user),
            format!("-mainchainrpcpassword={}", parent_rpc.password),
            format!(
                "-parentgenesisblockhash={}",
                parent_genesis.as_str().unwrap_or_default()
            ),
        ];
        args.extend(CHAIN_ARGS.iter().map(ToString::to_string));

        let mut node = Daemon::start(exe, workdir.join("sequentia"), rpc, &args)?;

        let network = ElementsRpc::new(
            format!("http://127.0.0.1:{}", node.rpc_port),
            Auth::UserPass(rpc.user.clone(), rpc.password.clone()),
        )
        .and_then(|rpc| rpc.sequentia_network());

        match network {
            Ok(network) => Ok((node, network)),
            Err(e) => {
                node.stop();
                Err(e.into())
            }
        }
    }

    fn workdir() -> Result<PathBuf, RegtestError> {
        let base = match std::env::var_os(DATADIR_ENV_NAME) {
            Some(dir) => PathBuf::from(dir),
            None => std::env::current_dir()?.join("target").join("simplex"),
        };
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());

        Ok(base.join(format!("sequentia-regtest-{}-{nanos}", std::process::id())))
    }

    /// The Sequentia chain, as read from its node.
    #[must_use]
    pub fn network(&self) -> SimplicityNetwork {
        self.network
    }

    /// The Sequentia node's RPC URL.
    #[must_use]
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.node.rpc_port)
    }

    /// The Sequentia node's RPC credentials.
    #[must_use]
    pub fn auth(&self) -> Auth {
        Auth::UserPass(self.rpc_user.clone(), self.rpc_password.clone())
    }

    /// Funds `address` with `atoms` of the chain's policy asset from the initial free coins, and
    /// confirms it. The node's wallet names the fee asset itself: nothing else determines it on a
    /// chain with the open fee market.
    ///
    /// # Errors
    /// Returns a `RegtestError` if a node call fails.
    pub fn fund(&self, address: &str, atoms: u64) -> Result<(), RegtestError> {
        let policy = self.network.policy_asset().to_string();
        let mine = self.node.call("getnewaddress", &["".into(), "bech32".into()])?;

        self.node.call("generatetoaddress", &[1.into(), mine.clone()])?;
        self.node.call("rescanblockchain", &[])?;
        // Subtracting the fee from the amount sent determines the fee asset.
        self.node.call(
            "sendtoaddress",
            &[mine.clone(), "21".into(), "".into(), "".into(), true.into()],
        )?;
        self.node.call("generatetoaddress", &[100.into(), mine.clone()])?;

        let amount = format!("{}.{:08}", atoms / 100_000_000, atoms % 100_000_000);

        self.node.call(
            "sendtoaddress",
            &[
                address.into(),
                amount.into(),
                "".into(),
                "".into(),
                false.into(),
                false.into(),
                1.into(),
                "UNSET".into(),
                false.into(),
                policy.clone().into(),
                true.into(),
                Value::Null,
                policy.into(),
            ],
        )?;
        self.node.call("generatetoaddress", &[1.into(), mine])?;

        Ok(())
    }

    /// Stops both nodes and deletes their data directories.
    pub fn kill(&mut self) {
        if self.stopped {
            return;
        }

        self.node.stop();
        self.parent.stop();
        let _ = std::fs::remove_dir_all(&self.workdir);
        self.stopped = true;
    }
}

impl Drop for SequentiaRegtestClient {
    fn drop(&mut self) {
        self.kill();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("a free local port")
}

fn random_password() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());

    format!("{:032x}", nanos ^ (u128::from(std::process::id()) << 64))
}
