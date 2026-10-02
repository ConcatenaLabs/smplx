use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use smplx_regtest::Regtest as RegtestRunner;
use smplx_regtest::{RegtestChain, RegtestConfig};

use crate::commands::error::CommandError;

pub struct Regtest {}

impl Regtest {
    /// Starts the regtest environment and blocks until terminated via Ctrl-C.
    ///
    /// # Errors
    /// Returns a `CommandError` if initializing the environment from the config fails, or if shutting down the client fails.
    ///
    /// # Panics
    /// Panics if setting the Ctrl-C handler fails, or if required RPC authentication credentials cannot be unwrapped.
    pub fn run(config: &RegtestConfig) -> Result<(), CommandError> {
        if config.chain == RegtestChain::Sequentia {
            return Self::run_sequentia(config);
        }

        // The client will be killed automatically via the Drop trait implementation
        let (client, signer) = RegtestRunner::from_config(config)?;

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        let main_thread = std::thread::current();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
            main_thread.unpark();
        })
        .expect("Error setting Ctrl-C handler");

        let auth = client.auth().get_user_pass().unwrap();

        println!("======================================");
        println!("Waiting for Ctrl-C...");
        println!();
        println!("RPC: {}", client.rpc_url());
        println!("Esplora: {}", client.esplora_url());
        println!("User: {:?}, Password: {:?}", auth.0.unwrap(), auth.1.unwrap());
        println!();
        println!("Signer: {:?}", signer.get_address());
        println!("======================================");

        while running.load(Ordering::SeqCst) {
            std::thread::park();
        }

        Ok(())
    }

    /// Starts a Sequentia regtest chain and blocks until terminated via Ctrl-C. The chain is read
    /// over the node's RPC; there is no Esplora.
    fn run_sequentia(config: &RegtestConfig) -> Result<(), CommandError> {
        let (client, signer) = RegtestRunner::sequentia_from_config(config)?;

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        let main_thread = std::thread::current();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
            main_thread.unpark();
        })
        .expect("Error setting Ctrl-C handler");

        let auth = client.auth().get_user_pass().unwrap();

        println!("======================================");
        println!("Waiting for Ctrl-C...");
        println!();
        println!("Sequentia RPC: {}", client.rpc_url());
        println!("User: {:?}, Password: {:?}", auth.0.unwrap(), auth.1.unwrap());
        println!("Genesis: {}", client.network().genesis_block_hash());
        println!("Policy asset: {}", client.network().policy_asset());
        println!();
        println!("Signer: {:?}", signer.get_address());
        println!("======================================");

        while running.load(Ordering::SeqCst) {
            std::thread::park();
        }

        Ok(())
    }
}
