use std::collections::HashMap;
#[cfg(feature = "provider")]
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use simplicityhl::Value;
use simplicityhl::WitnessValues;
use simplicityhl::elements::pset::PartiallySignedTransaction;
use simplicityhl::elements::secp256k1_zkp::{self, All, Keypair, Message, Secp256k1, ecdsa, schnorr};
use simplicityhl::elements::sighash::Prevouts;
use simplicityhl::elements::taproot::{LeafVersion, TapLeafHash};
use simplicityhl::elements::{Address, AssetId, LockTime, SchnorrSighashType, Script, Sequence, Transaction, TxOut};
#[cfg(feature = "provider")]
use simplicityhl::elements::{OutPoint, Txid};
use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;
use simplicityhl::simplicity::hashes::Hash;
use simplicityhl::str::WitnessName;
use simplicityhl::value::ValueConstructible;

use bip39::Mnemonic;
use bip39::rand::thread_rng;

use elements_miniscript::{
    ConfidentialDescriptor, Descriptor, DescriptorPublicKey,
    bitcoin::{PrivateKey, PublicKey, bip32::DerivationPath},
    elements::{
        EcdsaSighashType,
        bitcoin::bip32::{Fingerprint, Xpriv, Xpub},
        sighash::SighashCache,
    },
    elementssig_to_rawsig,
    psbt::PsbtExt,
    slip77::MasterBlindingKey,
};

use crate::constants::{
    CONTRACT_KEY_PURPOSE, DUST_RELAY_FEE, FEE_EXCHANGE_RATE_OVERRIDE_LIFETIME, FEE_EXCHANGE_RATE_SCALE,
};
use crate::program::logger::ProgramLogger;
use crate::program::{ProgramTrait, SpendBudget};
#[cfg(feature = "provider")]
use crate::provider::ProviderTrait;
use crate::provider::SimplicityNetwork;
use crate::signer::wtns_injector::WtnsInjector;
use crate::transaction::{
    ChangeOutput, FinalTransaction, PartialOutput, RequiredSignature, SigMessage, TapscriptInput, TapscriptWitness,
};
#[cfg(feature = "provider")]
use crate::transaction::{PartialInput, TxReceipt, UTXO};

use super::error::SignerError;

/// The length of the DER encoding of every ECDSA signature the signer makes.
const ECDSA_DER_LEN: usize = 70;

/// A placeholder dummy fee amount used during transaction estimation.
pub const PLACEHOLDER_FEE: u64 = 1;

/// Common signing interface spanning over standard explicit inputs and Simplicity programs.
pub trait SignerTrait {
    /// Generates a Schnorr signature to satisfy a target Simplicity program input.
    ///
    /// # Errors
    /// Returns a `SignerError` if the elements environment fails to build or if the message digest fails to construct.
    fn sign_program(
        &self,
        pst: &PartiallySignedTransaction,
        program: &dyn ProgramTrait,
        input_index: usize,
        network: &SimplicityNetwork,
        derivation_path: Option<&DerivationPath>,
        message: &SigMessage,
    ) -> Result<schnorr::Signature, SignerError>;

    /// Generates a BIP 341 signature (`SIGHASH_DEFAULT`) to spend an input through a tapscript leaf.
    ///
    /// # Errors
    /// Returns a `SignerError` if an input lacks its spent output or the sighash cannot be computed.
    fn sign_tapscript(
        &self,
        pst: &PartiallySignedTransaction,
        input_index: usize,
        leaf_script: &Script,
        network: &SimplicityNetwork,
        derivation_path: Option<&DerivationPath>,
    ) -> Result<schnorr::Signature, SignerError>;

    /// Generates an ECDSA signature to spend a standard transaction input.
    ///
    /// # Errors
    /// Returns a `SignerError` if the transaction formatting or sighash msg extraction fails.
    fn sign_input(
        &self,
        pst: &PartiallySignedTransaction,
        input_index: usize,
        derivation_path: Option<&DerivationPath>,
    ) -> Result<(PublicKey, ecdsa::Signature), SignerError>;
}

/// Core interface responsible for managing keys, interfacing with the blockchain provider,
/// assembling descriptors, estimating fees, and finalizing/signing transactions.
///
/// Without the `provider` feature the signer has no blockchain access: it can assemble,
/// blind, sign and finalize a transaction it is handed, but it cannot discover UTXOs,
/// look up a fee rate, or broadcast.
pub struct Signer {
    mnemonic: Mnemonic,
    xprv: Xpriv,
    #[cfg(feature = "provider")]
    provider: Option<Box<dyn ProviderTrait>>,
    network: SimplicityNetwork,
    secp: Secp256k1<All>,
    fee_asset: Option<AssetId>,
    fee_exchange_rates: HashMap<AssetId, RateOverride>,
    dust_relay_fee: u64,
}

/// An exchange rate set by hand, and how long it is trusted.
#[derive(Debug, Clone, Copy)]
struct RateOverride {
    rate: u64,
    // `None` where the SDK has no clock (a browser), and the rate cannot be aged.
    set_at: Option<Instant>,
    lifetime: Duration,
}

/// Now, where the standard library has a clock. In a browser (`wasm32-unknown-unknown`)
/// `Instant::now` panics, so there is none.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[allow(clippy::unnecessary_wraps)]
fn clock_now() -> Option<Instant> {
    Some(Instant::now())
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn clock_now() -> Option<Instant> {
    None
}

/// The asset a transaction's fee is paid in, and the rate at which the network values it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeAsset {
    /// The asset of the fee output, of the change, and of the coins the signer adds.
    pub asset: AssetId,
    /// Atoms of the asset per [`FEE_EXCHANGE_RATE_SCALE`] units of the fee rate's unit.
    pub exchange_rate: u64,
}

impl FeeAsset {
    /// Converts a fee in the fee rate's unit into atoms of the fee asset, rounding up, so the
    /// network never values the fee below what was asked.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn atoms(&self, reference_fee: u64) -> u64 {
        let scaled = u128::from(reference_fee) * u128::from(FEE_EXCHANGE_RATE_SCALE);

        scaled
            .div_ceil(u128::from(self.exchange_rate))
            .min(u128::from(u64::MAX)) as u64
    }

    /// The smallest explicit output of this asset to `script_pubkey` that the node relays, in the
    /// asset's own atoms, at a dust relay fee of `dust_relay_fee` reference units per 1,000
    /// vbytes.
    ///
    /// The node's rule (`GetDustThreshold`): an output is dust when it is worth less than spending
    /// it would cost, `ceil(dust_relay_fee × size / 1000)` reference units, where `size` is the
    /// output's serialized size plus 67 bytes for a witness program (a P2WPKH input's share) or
    /// 148 for any other script; that value is converted into the asset at its exchange rate,
    /// rounding up. So the threshold is valued, not counted: 14 atoms of an asset at par for a
    /// P2WPKH output, and one atom of an asset worth a thousand reference units an atom.
    #[must_use]
    pub fn dust_threshold(&self, script_pubkey: &Script, dust_relay_fee: u64) -> u64 {
        let output = TxOut {
            asset: simplicityhl::elements::confidential::Asset::Explicit(self.asset),
            value: simplicityhl::elements::confidential::Value::Explicit(0),
            nonce: simplicityhl::elements::confidential::Nonce::Null,
            script_pubkey: script_pubkey.clone(),
            witness: simplicityhl::elements::TxOutWitness::default(),
        };
        let spend = if script_pubkey.is_witness_program() {
            32 + 4 + 1 + 107 / 4 + 4
        } else {
            32 + 4 + 1 + 107 + 4
        };
        let size =
            u128::try_from(simplicityhl::elements::encode::serialize(&output).len() + spend).unwrap_or(u128::MAX);
        let mut reference = (u128::from(dust_relay_fee) * size).div_ceil(1_000);

        // As the node's `CFeeRate::GetFee`: a positive rate never values a cost at nothing.
        if reference == 0 && dust_relay_fee > 0 {
            reference = 1;
        }

        self.atoms(u64::try_from(reference).unwrap_or(u64::MAX))
    }
}

impl SignerTrait for Signer {
    fn sign_program(
        &self,
        pst: &PartiallySignedTransaction,
        program: &dyn ProgramTrait,
        input_index: usize,
        network: &SimplicityNetwork,
        derivation_path: Option<&DerivationPath>,
        message: &SigMessage,
    ) -> Result<schnorr::Signature, SignerError> {
        // A contract key signs the transaction's signature hash, or a tagged hash of it. A message
        // a closure derives could be anything, so it is signed only for a program that says so.
        if matches!(message, SigMessage::Custom(_)) && !program.declares_custom_sig_message() {
            return Err(SignerError::CustomSigMessageUndeclared(input_index));
        }

        let env = program.get_env(pst, input_index, network)?;
        let sighash = env.c_tx_env().sighash_all().to_byte_array();
        let msg = Message::from_digest(message.digest(sighash));

        let private_key = self.get_contract_private_key_at(derivation_path);
        let keypair = Keypair::from_secret_key(&self.secp, &private_key.inner);

        Ok(self.secp.sign_schnorr(&msg, &keypair))
    }

    fn sign_tapscript(
        &self,
        pst: &PartiallySignedTransaction,
        input_index: usize,
        leaf_script: &Script,
        network: &SimplicityNetwork,
        derivation_path: Option<&DerivationPath>,
    ) -> Result<schnorr::Signature, SignerError> {
        let tx = pst.extract_tx()?;
        let prevouts = pst
            .inputs()
            .iter()
            .enumerate()
            .map(|(index, input)| input.witness_utxo.clone().ok_or(SignerError::MissingSpentOutput(index)))
            .collect::<Result<Vec<TxOut>, _>>()?;

        let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::default());
        let sighash = SighashCache::new(&tx).taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            leaf_hash,
            SchnorrSighashType::Default,
            network.genesis_block_hash(),
        )?;
        let msg = Message::from_digest(sighash.to_byte_array());

        let private_key = self.get_contract_private_key_at(derivation_path);
        let keypair = Keypair::from_secret_key(&self.secp, &private_key.inner);

        Ok(self.secp.sign_schnorr(&msg, &keypair))
    }

    fn sign_input(
        &self,
        pst: &PartiallySignedTransaction,
        input_index: usize,
        derivation_path: Option<&DerivationPath>,
    ) -> Result<(PublicKey, ecdsa::Signature), SignerError> {
        let tx = pst.extract_tx()?;

        let mut sighash_cache = SighashCache::new(&tx);
        let genesis_hash = elements_miniscript::elements::BlockHash::all_zeros();

        let message = pst
            .sighash_msg(input_index, &mut sighash_cache, None, genesis_hash)?
            .to_secp_msg();

        let private_key = self.get_private_key_at(derivation_path);
        let public_key = private_key.public_key(&self.secp);

        Ok((public_key, self.sign_ecdsa_fixed_length(&message, &private_key.inner)))
    }
}

/// What a spend will weigh and cost, worked out before its final signatures.
///
/// The signer works it out on a draft of the transaction: the same inputs, programs, padding
/// and outputs, with placeholder amounts in the change and fee outputs. Every part of a spend has
/// a size fixed before it is signed (a Schnorr signature is 64 bytes, every ECDSA signature the
/// signer makes is 71 with its sighash byte, a Simplicity program's pruned form and padding do
/// not depend on its signature), so the final transaction weighs what its draft did and its fee
/// is right the first time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendEstimate {
    /// The weight of the signed transaction.
    pub weight: usize,
    /// Its virtual size: the weight divided by four, rounded up.
    pub vsize: usize,
    /// The fee, in atoms of the fee asset.
    pub fee: u64,
    /// The asset the fee is paid in.
    pub fee_asset: AssetId,
    /// Whether the transaction keeps a change output.
    pub change: bool,
    /// For each Simplicity input, by index: what its program costs and what its witness earns,
    /// padding included.
    pub budgets: Vec<(usize, SpendBudget)>,
}

/// A transaction whose amounts are settled, and what its draft weighed.
struct Plan {
    fee_tx: FinalTransaction,
    fee: u64,
    weight: usize,
    vsize: usize,
    fee_weight: usize,
    change: bool,
    budgets: Vec<(usize, SpendBudget)>,
}

enum Estimate {
    Success(Box<Plan>),
    Failure(u64),
}

// TODO: refactor descriptors to be a standalone object to specify custom derivation paths.
impl Signer {
    /// Creates a new `Signer` instance seeded from the provided mnemonic and paired with the specified provider.
    ///
    /// # Panics
    /// Panics if the mnemonic fails to parse, or if deriving the master private key fails.
    #[cfg(feature = "provider")]
    #[must_use]
    pub fn new(mnemonic: &str, provider: Box<dyn ProviderTrait>) -> Self {
        let network = *provider.get_network();
        let mut signer = Self::from_mnemonic(mnemonic, network);

        signer.provider = Some(provider);

        signer
    }

    /// Creates a `Signer` from a mnemonic and an explicit network, with no blockchain access.
    ///
    /// This is the constructor a host with its own networking and its own key custody should use.
    ///
    /// # Panics
    /// Panics if the mnemonic fails to parse, or if deriving the master private key fails.
    #[must_use]
    pub fn from_mnemonic(mnemonic: &str, network: SimplicityNetwork) -> Self {
        let secp = Secp256k1::new();
        let mnemonic: Mnemonic = mnemonic
            .parse()
            .map_err(|e: bip39::Error| SignerError::Mnemonic(e.to_string()))
            .unwrap();

        let seed = mnemonic.to_seed("");
        let xprv = Xpriv::new_master(network, &seed).unwrap();

        Self {
            mnemonic,
            xprv,
            #[cfg(feature = "provider")]
            provider: None,
            network,
            secp,
            fee_asset: None,
            fee_exchange_rates: HashMap::new(),
            dust_relay_fee: DUST_RELAY_FEE,
        }
    }

    /// Takes the node's dust relay fee to be `rate` reference units per 1,000 vbytes, for a node
    /// started with a `-dustrelayfee` other than the default [`DUST_RELAY_FEE`]. The signer keeps
    /// change only when the node would relay it; see [`FeeAsset::dust_threshold`].
    #[must_use]
    pub fn with_dust_relay_fee(mut self, rate: u64) -> Self {
        self.dust_relay_fee = rate;

        self
    }

    /// Pays every fee this signer builds in `asset`.
    ///
    /// On a network whose fees are fixed to its policy asset, any other asset is refused when a
    /// transaction is built.
    #[must_use]
    pub fn with_fee_asset(mut self, asset: AssetId) -> Self {
        self.fee_asset = Some(asset);

        self
    }

    /// Values fees paid in `asset` at `rate` (atoms per [`FEE_EXCHANGE_RATE_SCALE`] units of the
    /// fee rate's unit) instead of asking the provider, for
    /// [`FEE_EXCHANGE_RATE_OVERRIDE_LIFETIME`] from now. A signer with no provider that reads the
    /// node's rates needs this for every fee asset.
    ///
    /// Once the lifetime has passed, a fee in `asset` is refused with
    /// `SignerError::FeeExchangeRateExpired` until the rate is set again: a node values fees at its
    /// own rate when the transaction reaches it, and an old rate can underpay. In a browser
    /// (`wasm32-unknown-unknown`) the SDK has no clock, so there the rate does not age, and the
    /// host sets it afresh before each transaction.
    #[must_use]
    pub fn with_fee_exchange_rate(self, asset: AssetId, rate: u64) -> Self {
        self.with_fee_exchange_rate_for(asset, rate, FEE_EXCHANGE_RATE_OVERRIDE_LIFETIME)
    }

    /// As [`Self::with_fee_exchange_rate`], trusted for `lifetime` from now.
    #[must_use]
    pub fn with_fee_exchange_rate_for(mut self, asset: AssetId, rate: u64, lifetime: Duration) -> Self {
        self.fee_exchange_rates.insert(
            asset,
            RateOverride {
                rate,
                set_at: clock_now(),
                lifetime,
            },
        );

        self
    }

    /// Decides the asset a transaction's fee is paid in.
    ///
    /// On a network whose fees are fixed to its policy asset, that asset. Elsewhere the asset set
    /// with [`Self::with_fee_asset`]; failing that, the one asset the transaction moves, leaving
    /// out reissuance tokens and the assets it creates
    /// ([`FinalTransaction::fee_asset_candidates`]); failing that, an error. No asset is a
    /// fallback.
    ///
    /// # Errors
    /// Returns `FeeAssetNotAccepted` for a fee asset the network cannot take, and `FeeAssetUnset`
    /// when nothing names the asset.
    pub fn fee_asset_for(&self, tx: &FinalTransaction) -> Result<AssetId, SignerError> {
        if self.network.fee_asset_is_fixed() {
            let policy = self.network.policy_asset();

            return match self.fee_asset {
                Some(asset) if asset != policy => Err(SignerError::FeeAssetNotAccepted(asset)),
                _ => Ok(policy),
            };
        }

        if let Some(asset) = self.fee_asset {
            return Ok(asset);
        }

        let candidates = tx.fee_asset_candidates();

        match (candidates.len(), candidates.first()) {
            (1, Some(asset)) => Ok(*asset),
            _ => Err(SignerError::FeeAssetUnset(
                tx.moved_assets()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
        }
    }

    /// The rate at which the network values fees paid in `asset`: the one set with
    /// [`Self::with_fee_exchange_rate`] while it lasts, else the node's, read through the provider
    /// at every call.
    ///
    /// # Errors
    /// Returns `FeeExchangeRateExpired` for a rate set by hand that is past its lifetime,
    /// `NoFeeExchangeRateSource` when nothing can give a rate, and `FeeAssetNotAccepted` when the
    /// node lists no positive rate for the asset.
    pub fn fee_exchange_rate(&self, asset: AssetId) -> Result<u64, SignerError> {
        if let Some(set) = self.fee_exchange_rates.get(&asset) {
            let age = set.set_at.map_or(Duration::ZERO, |set_at| set_at.elapsed());

            if age > set.lifetime {
                return Err(SignerError::FeeExchangeRateExpired {
                    asset,
                    age_secs: age.as_secs(),
                    lifetime_secs: set.lifetime.as_secs(),
                });
            }

            return Self::positive_rate(asset, Some(set.rate));
        }

        if self.network.fee_asset_is_fixed() && asset == self.network.policy_asset() {
            return Ok(FEE_EXCHANGE_RATE_SCALE);
        }

        #[cfg(feature = "provider")]
        if let Some(provider) = self.provider.as_deref() {
            if !provider.has_fee_exchange_rates() {
                return Err(SignerError::NoFeeExchangeRateSource(asset));
            }

            return Self::positive_rate(asset, provider.fetch_fee_exchange_rate(asset)?);
        }

        Err(SignerError::NoFeeExchangeRateSource(asset))
    }

    fn positive_rate(asset: AssetId, rate: Option<u64>) -> Result<u64, SignerError> {
        match rate {
            Some(rate) if rate > 0 => Ok(rate),
            _ => Err(SignerError::FeeAssetNotAccepted(asset)),
        }
    }

    fn fee_asset_quote(&self, tx: &FinalTransaction) -> Result<FeeAsset, SignerError> {
        let asset = self.fee_asset_for(tx)?;

        Ok(FeeAsset {
            asset,
            exchange_rate: self.fee_exchange_rate(asset)?,
        })
    }

    /// Composes, funds, and broadcasts a transaction sending `amount` of the network's default
    /// asset, its policy asset. A network with no default asset refuses it: name the asset with
    /// [`Self::send_asset`].
    ///
    /// # Errors
    /// Returns `AssetUnnamed` on a network with no default asset, and otherwise a `SignerError` if
    /// compiling the inputs fails, there are insufficient funds/fees, or broadcast is rejected.
    #[cfg(feature = "provider")]
    pub fn send(&self, to: Script, amount: u64) -> Result<TxReceipt<'_>, SignerError> {
        let asset = self.network.default_asset().ok_or(SignerError::AssetUnnamed)?;

        self.send_asset(to, amount, asset)
    }

    /// Composes, funds, and broadcasts a transaction sending `amount` of `asset`.
    ///
    /// The signer funds only the fee asset, so this works when `asset` is the fee asset: set
    /// with [`Self::with_fee_asset`], or, where the network has no fixed fee asset, the asset sent.
    ///
    /// # Errors
    /// Returns a `SignerError` if compiling the inputs fails, there are insufficient funds/fees, or broadcast is rejected.
    #[cfg(feature = "provider")]
    pub fn send_asset(&self, to: Script, amount: u64, asset: AssetId) -> Result<TxReceipt<'_>, SignerError> {
        let mut ft = FinalTransaction::new();

        ft.add_output(PartialOutput::new(to, amount, asset));

        let (tx, _fee) = self.finalize(&ft)?;

        Ok(self.get_provider()?.broadcast_transaction(&tx)?)
    }

    /// Evaluates, funds, and broadcasts an already assembled `FinalTransaction`.
    ///
    /// # Errors
    /// Returns a `SignerError` if finalizing the payload fails or if the network rejects the broadcast.
    #[cfg(feature = "provider")]
    pub fn broadcast(&self, tx: &FinalTransaction) -> Result<TxReceipt<'_>, SignerError> {
        let (tx, _fee) = self.finalize(tx)?;

        Ok(self.get_provider()?.broadcast_transaction(&tx)?)
    }

    /// Evaluates the input components of a `FinalTransaction`, iteratively selecting available wallet UTXOs to cover outputs and estimated fees.
    ///
    /// # Errors
    /// Returns a `SignerError` if the wallet contains insufficient funds to satisfy output values and target fee rates.
    #[cfg(feature = "provider")]
    pub fn finalize(&self, tx: &FinalTransaction) -> Result<(Transaction, u64), SignerError> {
        let fee_asset = self.fee_asset_quote(tx)?;
        let mut signer_utxos = self.get_utxos_asset(fee_asset.asset)?;
        let mut set = HashSet::new();

        for input in tx.inputs() {
            set.insert(OutPoint {
                txid: input.partial_input.witness_txid,
                vout: input.partial_input.witness_output_index,
            });
        }

        signer_utxos.retain(|utxo| !set.contains(&utxo.outpoint));

        // Descending sort of both confidential and explicit utxos
        signer_utxos.sort_by_key(|utxo| std::cmp::Reverse(utxo.amount()));

        let mut fee_tx = tx.clone();
        // A fee is at least one atom; each estimate that falls short says what it needs.
        let mut curr_fee = 1u64;
        let fee_rate = self.get_provider()?.fetch_fee_rate(1)?;

        let try_estimate = |fee_tx: &FinalTransaction, policy_amount_delta: i64, curr_fee: &mut u64| match self
            .estimate_tx(
                fee_tx.clone(),
                fee_rate,
                &fee_asset,
                policy_amount_delta.cast_unsigned(),
            ) {
            Ok(Estimate::Success(plan)) => {
                let signed = self.sign_plan(&plan);
                ProgramLogger::flush_logs();
                signed.map(Some)
            }
            Ok(Estimate::Failure(required_fee)) => {
                *curr_fee = required_fee;
                Ok(None)
            }
            Err(err) => {
                ProgramLogger::flush_logs();
                Err(err)
            }
        };

        for utxo in signer_utxos {
            let policy_amount_delta = fee_tx.calculate_fee_delta_in(fee_asset.asset);

            if policy_amount_delta >= curr_fee.cast_signed()
                && let Some(result) = try_estimate(&fee_tx, policy_amount_delta, &mut curr_fee)?
            {
                return Ok(result);
            }

            // IMPORTANT: must be added to the end of the transaction.
            // Otherwise, the logging of execution traces will be broken
            fee_tx.add_input(PartialInput::new(utxo), RequiredSignature::NativeEcdsa);
        }

        // need to try one more time after the loop
        let policy_amount_delta = fee_tx.calculate_fee_delta_in(fee_asset.asset);

        if policy_amount_delta >= curr_fee.cast_signed()
            && let Some(result) = try_estimate(&fee_tx, policy_amount_delta, &mut curr_fee)?
        {
            return Ok(result);
        }

        Err(SignerError::NotEnoughFunds(curr_fee))
    }

    /// Verifies and finalizes a transaction against a strict target confirmation window (in blocks).
    /// This function also assumes that the transaction already includes the coin selection.
    ///
    /// # Errors
    /// Returns a `SignerError` if the assembled inputs do not meet dust limits or fail to cover the
    /// dynamically estimated required fee.
    pub fn finalize_strict(&self, tx: &FinalTransaction, fee_rate: f32) -> Result<(Transaction, u64), SignerError> {
        let fee_asset = self.fee_asset_quote(tx)?;
        let policy_amount_delta = tx.calculate_fee_delta_in(fee_asset.asset);

        if policy_amount_delta < 1 {
            return Err(SignerError::DustAmount(policy_amount_delta));
        }

        // policy_amount_delta will be > 0
        match self.estimate_tx(tx.clone(), fee_rate, &fee_asset, policy_amount_delta.cast_unsigned())? {
            Estimate::Success(plan) => {
                let signed = self.sign_plan(&plan);
                ProgramLogger::flush_logs();
                signed
            }
            Estimate::Failure(required_fee) => Err(SignerError::NotEnoughFeeAmount(policy_amount_delta, required_fee)),
        }
    }

    /// Reports what an assembled transaction would cost in fees at the given rate.
    ///
    /// # Errors
    /// Returns a `SignerError` if the transaction cannot be signed.
    pub fn estimate_fee(&self, tx: &FinalTransaction, fee_rate: f32) -> Result<u64, SignerError> {
        let fee_asset = self.fee_asset_quote(tx)?;
        let available_delta = tx.calculate_fee_delta_in(fee_asset.asset).max(0).cast_unsigned();
        let estimate = self.estimate_tx(tx.clone(), fee_rate, &fee_asset, available_delta);

        ProgramLogger::flush_logs();

        Ok(match estimate? {
            Estimate::Success(plan) => plan.fee,
            Estimate::Failure(fee) => fee,
        })
    }

    /// Works out what an assembled transaction will weigh and cost at the given fee rate, before
    /// it is signed: the weight of the transaction that [`Self::finalize_strict`] returns for it,
    /// and its fee in the fee asset's own atoms.
    ///
    /// # Errors
    /// Returns a `SignerError` if a program does not run, if the transaction cannot be padded, or
    /// if its inputs do not cover the fee (`NotEnoughFeeAmount`).
    pub fn estimate_spend(&self, tx: &FinalTransaction, fee_rate: f32) -> Result<SpendEstimate, SignerError> {
        let fee_asset = self.fee_asset_quote(tx)?;
        let available = tx.calculate_fee_delta_in(fee_asset.asset);
        let estimate = self.estimate_tx(tx.clone(), fee_rate, &fee_asset, available.max(0).cast_unsigned());

        ProgramLogger::flush_logs();

        match estimate? {
            Estimate::Success(plan) => Ok(SpendEstimate {
                weight: plan.weight,
                vsize: plan.vsize,
                fee: plan.fee,
                fee_asset: fee_asset.asset,
                change: plan.change,
                budgets: plan.budgets,
            }),
            Estimate::Failure(required) => Err(SignerError::NotEnoughFeeAmount(available, required)),
        }
    }

    /// Returns a reference to the active configured network provider.
    ///
    /// # Errors
    /// Returns `ProviderUnavailable` when the signer was built without one.
    #[cfg(feature = "provider")]
    pub fn get_provider(&self) -> Result<&dyn ProviderTrait, SignerError> {
        self.provider.as_deref().ok_or(SignerError::ProviderUnavailable)
    }

    /// Returns the confidential elements address matching the local wallet logic.
    ///
    /// # Panics
    /// Panics if the SLIP77 descriptor cannot be generated or parsed, or if address derivation fails.
    #[must_use]
    pub fn get_confidential_address(&self) -> Address {
        let mut descriptor =
            ConfidentialDescriptor::<DescriptorPublicKey>::from_str(&self.get_slip77_descriptor().unwrap())
                .map_err(|e| SignerError::Slip77Descriptor(e.to_string()))
                .unwrap();

        // Confidential descriptor doesn't support multipath
        descriptor.descriptor = descriptor.descriptor.into_single_descriptors().unwrap()[0].clone();

        descriptor
            .at_derivation_index(0)
            .unwrap()
            .address(&self.secp, self.network.address_params())
            .unwrap()
    }

    /// Returns the standard unblinded address matching the local wallet logic.
    ///
    /// # Panics
    /// Panics if the WPKH descriptor cannot be generated or parsed, or if address derivation fails.
    #[must_use]
    pub fn get_address(&self) -> Address {
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&self.get_wpkh_descriptor().unwrap())
            .map_err(|e| SignerError::WpkhDescriptor(e.to_string()))
            .unwrap();

        descriptor.into_single_descriptors().unwrap()[0]
            .at_derivation_index(0)
            .unwrap()
            .address(self.network.address_params())
            .unwrap()
    }

    /// Iterates against the network provider to select and unblind all known UTXOs.
    ///
    /// # Errors
    /// Returns a `SignerError` if querying the network or unblinding operations fail.
    #[cfg(feature = "provider")]
    pub fn get_utxos(&self) -> Result<Vec<UTXO>, SignerError> {
        self.get_utxos_filter(&|_| true, &|_| true)
    }

    /// Finds all known UTXOs belonging to the specific `AssetId`.
    ///
    /// # Errors
    /// Returns a `SignerError` if network interaction or confidential output decryption fails.
    #[cfg(feature = "provider")]
    pub fn get_utxos_asset(&self, asset: AssetId) -> Result<Vec<UTXO>, SignerError> {
        self.get_utxos_filter(&|utxo| utxo.asset() == asset, &|utxo| utxo.asset() == asset)
    }

    /// Finds all known UTXOs deriving from a targeted `Txid`.
    ///
    /// # Errors
    /// Returns a `SignerError` if querying the network fails.
    // TODO: can this be optimized to not populate TxOuts that are filtered out?
    #[cfg(feature = "provider")]
    pub fn get_utxos_txid(&self, txid: Txid) -> Result<Vec<UTXO>, SignerError> {
        self.get_utxos_filter(&|utxo| utxo.outpoint.txid == txid, &|utxo| utxo.outpoint.txid == txid)
    }

    /// Maps UTXOs retrieved from the provider through arbitrary functional filters.
    /// Separate filtering criteria apply explicitly vs confidentially.
    ///
    /// # Errors
    /// Returns a `SignerError` if retrieving remote outputs or executing confidential node unblinding throws an error.
    #[cfg(feature = "provider")]
    pub fn get_utxos_filter(
        &self,
        explicit_filter: &dyn Fn(&UTXO) -> bool,
        confidential_filter: &dyn Fn(&UTXO) -> bool,
    ) -> Result<Vec<UTXO>, SignerError> {
        // Fetch explicit and confidential utxos
        let mut all_utxos = self
            .get_provider()?
            .fetch_address_utxos(&self.get_confidential_address())?;

        // Filter out only confidential utxos and unblind them
        let mut confidential_utxos = self.unblind(
            all_utxos
                .iter()
                .filter(|utxo| utxo.txout.value.is_confidential())
                .cloned()
                .collect(),
        )?;
        // Leave only explicit utxos
        all_utxos.retain(|utxo| !utxo.txout.value.is_confidential());

        all_utxos.retain(explicit_filter);
        confidential_utxos.retain(confidential_filter);

        // Push unblinded utxos to explicit ones
        all_utxos.extend(confidential_utxos);

        Ok(all_utxos)
    }

    /// The x-only public key of the signer's default contract key, the key at `0/0` under the
    /// contract account (see [`Self::get_contract_private_key_at`]): the key a Simplicity program
    /// or a tapscript leaf names to be spent by this signer.
    #[must_use]
    pub fn get_schnorr_public_key(&self) -> XOnlyPublicKey {
        self.get_contract_public_key_at(None)
    }

    /// The x-only public key of the contract key at `relative` (see
    /// [`Self::get_contract_private_key_at`]).
    #[must_use]
    pub fn get_contract_public_key_at(&self, relative: Option<&DerivationPath>) -> XOnlyPublicKey {
        let private_key = self.get_contract_private_key_at(relative);
        let keypair = Keypair::from_secret_key(&self.secp, &private_key.inner);

        keypair.x_only_public_key().0
    }

    /// Derives a contract key: a key that signs for Simplicity programs and tapscript leaves, at
    /// a path relative to the contract account `m/8383h/{coin}h/0h`
    /// ([`CONTRACT_KEY_PURPOSE`]). `None` defaults to `0/0`.
    ///
    /// The wallet's own keys, which hold its funding and its change, sit under
    /// `m/84h/{coin}h/0h` ([`Self::get_private_key_at`]); a contract key is never one of them.
    ///
    /// # Panics
    /// Panics if the master private key or derivation path cannot be derived.
    #[must_use]
    pub fn get_contract_private_key_at(&self, relative: Option<&DerivationPath>) -> PrivateKey {
        let account = self.get_contract_derivation_path().unwrap();

        self.derive_relative(&account, relative)
    }

    /// Resolves the standard format ECDSA public key.
    #[must_use]
    pub fn get_ecdsa_public_key(&self) -> PublicKey {
        self.get_private_key().public_key(&self.secp)
    }

    /// Resolves the corresponding blinding public key.
    #[must_use]
    pub fn get_blinding_public_key(&self) -> PublicKey {
        self.get_blinding_private_key().public_key(&self.secp)
    }

    /// Internally derives and exposes the wallet's signing active private key.
    ///
    /// # Panics
    /// Panics if the master private key or derivation path cannot be derived.
    #[must_use]
    pub fn get_private_key(&self) -> PrivateKey {
        self.get_private_key_at(None)
    }

    /// Derives a wallet key, which signs the wallet's own (ECDSA) inputs, at a path relative to
    /// the wallet account `m/84h/{coin}h/0h`. `None` defaults to `0/0`, the wallet's address.
    ///
    /// # Panics
    /// Panics if the master private key or derivation path cannot be derived.
    #[must_use]
    pub fn get_private_key_at(&self, relative: Option<&DerivationPath>) -> PrivateKey {
        let account = self.get_derivation_path().unwrap();

        self.derive_relative(&account, relative)
    }

    fn derive_relative(&self, full_path: &DerivationPath, relative: Option<&DerivationPath>) -> PrivateKey {
        let master_xprv = self.master_xpriv().unwrap();

        let default_path;
        let relative = if let Some(path) = relative {
            path
        } else {
            default_path = DerivationPath::from_str("0/0")
                .map_err(|e| SignerError::DerivationPath(e.to_string()))
                .unwrap();

            &default_path
        };

        let derived = full_path.extend(relative);
        let ext_derived = master_xprv.derive_priv(&self.secp, &derived).unwrap();

        PrivateKey::new(ext_derived.private_key, self.network)
    }

    /// Generates the private key linked to confidential payload blinding.
    ///
    /// The generated `PrivateKey` is associated with the `Test` (non-Bitcoin/Liquid-mainnet) network kind.
    /// Retrieves the blinding private key derived from the master SLIP77 key and the script public key of the address.
    ///
    /// # Panics
    /// Panics if the master SLIP77 key cannot be derived.
    #[must_use]
    pub fn get_blinding_private_key(&self) -> PrivateKey {
        let blinding_key = self
            .master_slip77()
            .unwrap()
            .blinding_private_key(&self.get_address().script_pubkey());

        PrivateKey::new(blinding_key, self.network)
    }

    #[cfg(feature = "provider")]
    fn unblind(&self, utxos: Vec<UTXO>) -> Result<Vec<UTXO>, SignerError> {
        let mut unblinded: Vec<UTXO> = Vec::new();

        for mut utxo in utxos {
            let blinding_key = self.get_blinding_private_key();
            let secrets = utxo.txout.unblind(&self.secp, blinding_key.inner)?;

            utxo.secrets = Some(secrets);

            unblinded.push(utxo);
        }

        Ok(unblinded)
    }

    fn estimate_tx(
        &self,
        mut fee_tx: FinalTransaction,
        fee_rate: f32,
        fee_asset: &FeeAsset,
        available_delta: u64,
    ) -> Result<Estimate, SignerError> {
        // Estimate the tx fee with the change. The caller supplies the change target
        let change = if let Some(target) = fee_tx.change() {
            target.clone()
        } else {
            let change = ChangeOutput::new(self.get_address().script_pubkey());

            // A confidential input with no other blinded output can only balance against a
            // blinded change, whatever the network's default.
            let must_blind = fee_tx.has_confidential_input() && !fee_tx.needs_blinding();

            if self.network.confidential_change_by_default() || must_blind {
                change.with_blinding_key(self.get_blinding_public_key())
            } else {
                change
            }
        };

        // A confidential input with an explicit change target and no blinded
        // output cannot be balanced, which the node rejects with `bad-txns-in-ne-out`.
        if fee_tx.has_confidential_input() && !fee_tx.needs_blinding() && change.blinding_key.is_none() {
            return Err(SignerError::ConfidentialInputWithoutBlindedOutput);
        }

        let mut change_output = PartialOutput::new(change.script_pubkey.clone(), PLACEHOLDER_FEE, fee_asset.asset);

        if let Some(blinding_key) = change.blinding_key {
            change_output = change_output.with_blinding_key(blinding_key);
        }

        fee_tx.add_output(change_output);

        fee_tx.add_output(PartialOutput::new(Script::new(), PLACEHOLDER_FEE, fee_asset.asset));

        // The draft weighs what the final transaction will: only amounts change between them.
        let (draft, budgets) = self.sign_tx_reporting(&fee_tx)?;
        let fee = fee_asset.atoms(fee_tx.calculate_fee(self.fee_weight(&draft), fee_rate));
        // Change below what the node relays is not kept: it joins the fee. At or above it, it is.
        let dust = fee_asset
            .dust_threshold(&change.script_pubkey, self.dust_relay_fee)
            .max(1);

        if available_delta >= fee.saturating_add(dust) {
            // We have enough funds to cover the change UTXO
            let outputs = fee_tx.outputs_mut();

            outputs[outputs.len() - 2].amount = available_delta - fee;
            outputs[outputs.len() - 1].amount = fee;

            if !fee_tx.is_balanced() {
                return Err(SignerError::Unbalanced());
            }

            return Ok(Estimate::Success(Box::new(
                self.plan(fee_tx, fee, &draft, true, budgets),
            )));
        }

        // Not enough funds for the change, so estimate without it.
        // Dropping the change is only safe while something else stays blinded.
        // When it is the transaction's only blinded output and an input is confidential,
        // removing it makes the transaction unblindable.
        let change_index = fee_tx.n_outputs() - 2;
        let blinded_without_change = fee_tx
            .outputs()
            .iter()
            .enumerate()
            .any(|(index, output)| index != change_index && output.blinding_key.is_some());

        if fee_tx.has_confidential_input() && !blinded_without_change {
            return Ok(Estimate::Failure(fee.saturating_add(dust)));
        }

        fee_tx.remove_output(change_index);

        let (draft, budgets) = self.sign_tx_reporting(&fee_tx)?;
        let fee = fee_asset.atoms(fee_tx.calculate_fee(self.fee_weight(&draft), fee_rate));

        if available_delta < fee {
            return Ok(Estimate::Failure(fee));
        }

        let outputs = fee_tx.outputs_mut();

        // Change the fee output amount
        outputs[outputs.len() - 1].amount = available_delta;

        if !fee_tx.is_balanced() {
            return Err(SignerError::Unbalanced());
        }

        // The fee is what is left: at least what the weight asks.
        Ok(Estimate::Success(Box::new(self.plan(
            fee_tx,
            available_delta,
            &draft,
            false,
            budgets,
        ))))
    }

    fn plan(
        &self,
        fee_tx: FinalTransaction,
        fee: u64,
        draft: &Transaction,
        change: bool,
        budgets: Vec<(usize, SpendBudget)>,
    ) -> Plan {
        Plan {
            fee_tx,
            fee,
            weight: draft.weight(),
            vsize: draft.vsize(),
            fee_weight: self.fee_weight(draft),
            change,
            budgets,
        }
    }

    /// Signs a settled transaction. It weighs what its draft did; were it heavier, its fee would be
    /// short, so that is refused rather than broadcast.
    fn sign_plan(&self, plan: &Plan) -> Result<(Transaction, u64), SignerError> {
        let tx = self.sign_tx(&plan.fee_tx)?;
        let signed = self.fee_weight(&tx);

        if signed > plan.fee_weight {
            return Err(SignerError::WeightAboveEstimate {
                estimated: plan.fee_weight,
                signed,
            });
        }

        Ok((tx, plan.fee))
    }

    /// The weight the network charges a fee on.
    fn fee_weight(&self, tx: &Transaction) -> usize {
        if self.network.discounted_ct_fees() {
            tx.discount_weight()
        } else {
            tx.weight()
        }
    }

    fn sign_tx(&self, tx: &FinalTransaction) -> Result<Transaction, SignerError> {
        Ok(self.sign_tx_reporting(tx)?.0)
    }

    /// Signs and finalizes a transaction, and reports each Simplicity input's cost and budget.
    fn sign_tx_reporting(
        &self,
        tx: &FinalTransaction,
    ) -> Result<(Transaction, Vec<(usize, SpendBudget)>), SignerError> {
        let (mut pst, secrets) = tx.extract_pst();

        if tx.needs_blinding() {
            pst.blind_last(&mut thread_rng(), &self.secp, &secrets)?;
        }

        // A full signature hash over a Simplicity input commits to every input's annex, so every
        // annex is fixed before the signatures that count are made. The first pass signs with
        // none and learns what each program costs and what its witness earns; when some program
        // needs padding, the next pass puts each annex in place first and signs again. Padding
        // does not change a program, so the second pass normally settles it; a third covers a
        // program that reads its own annex.
        let mut annexes: Vec<Option<Vec<u8>>> = vec![None; tx.n_inputs()];

        for _ in 0..3 {
            // An input not yet signed holds `[placeholder, annex]`: BIP 341 reads an annex only
            // from a stack of two or more items, and so does the node.
            for (input, annex) in pst.inputs_mut().iter_mut().zip(&annexes) {
                input.final_script_witness = annex.clone().map(|annex| vec![Vec::new(), annex]);
            }

            let mut budgets = Vec::new();

            if !self.sign_inputs(tx, &mut pst, &mut annexes, &mut budgets)? {
                return Ok((pst.extract_tx()?, budgets));
            }
        }

        Err(SignerError::PaddingUnsettled)
    }

    /// Signs and finalizes every input with the given annexes in place. Returns whether some
    /// Simplicity input needs more padding than it was given, having recorded what it needs.
    fn sign_inputs(
        &self,
        tx: &FinalTransaction,
        pst: &mut PartiallySignedTransaction,
        annexes: &mut [Option<Vec<u8>>],
        budgets: &mut Vec<(usize, SpendBudget)>,
    ) -> Result<bool, SignerError> {
        let rule = self.network.simplicity_budget();
        let mut short = false;

        for (index, input_i) in tx.inputs().iter().enumerate() {
            // We need to prune the program
            if let Some(program_input) = &input_i.program_input {
                let signing_info: Option<(&String, &[String], &SigMessage)> = match &input_i.required_sig {
                    RequiredSignature::Witness(wtns_name) => Some((wtns_name, &[], &SigMessage::Sighash)),
                    RequiredSignature::WitnessWithPath(wtns_name, sig_path) => {
                        Some((wtns_name, sig_path, &SigMessage::Sighash))
                    }
                    RequiredSignature::WitnessWithMessage(wtns_name, sig_path, message) => {
                        Some((wtns_name, sig_path, message))
                    }
                    _ => None,
                };

                let signed_witness = match signing_info {
                    // Sign the program and inject the signature into the witness
                    Some((witness_name, sig_path, message)) => self.get_signed_program_witness(
                        pst,
                        program_input.program.as_ref(),
                        &program_input.witness.build_witness(),
                        witness_name,
                        sig_path,
                        index,
                        input_i.partial_input.derivation_path.as_ref(),
                        message,
                    )?,
                    // Just build the witness
                    None => program_input.witness.build_witness(),
                };

                let spend = program_input
                    .program
                    .finalize_spend(pst, &signed_witness, index, &self.network)
                    .map_err(|source| SignerError::CovenantExecution {
                        index,
                        locktime: pst.locktime().map_or(0, LockTime::to_consensus_u32),
                        sequence: pst.inputs()[index]
                            .sequence
                            .map_or(u32::MAX, Sequence::to_consensus_u32),
                        source,
                    })?;

                let mut stack = spend.stack;

                if let Some(annex) = &annexes[index] {
                    stack.push(annex.clone());
                }

                if !rule.covers(spend.cost, &stack) {
                    if annexes[index].is_some() {
                        stack.pop();
                    }

                    annexes[index] = rule
                        .padding(spend.cost, &stack)
                        .map_err(|source| SignerError::Budget { index, source })?;
                    short = true;
                }

                budgets.push((index, rule.report(spend.cost, &stack)));
                pst.inputs_mut()[index].final_script_witness = Some(stack);
            } else if let Some(tapscript) = &input_i.tapscript_input {
                let witness =
                    self.tapscript_witness(pst, index, tapscript, input_i.partial_input.derivation_path.as_ref())?;

                pst.inputs_mut()[index].final_script_witness = Some(witness);
            } else {
                // We need to sign the UTXO as is
                // TODO: do we always sign?
                let signed_witness = self.sign_input(pst, index, input_i.partial_input.derivation_path.as_ref())?;
                let raw_sig = elementssig_to_rawsig(&(signed_witness.1, EcdsaSighashType::All));

                pst.inputs_mut()[index].final_script_witness = Some(vec![raw_sig, signed_witness.0.to_bytes()]);
            }
        }

        Ok(short)
    }

    /// An ECDSA signature whose DER encoding is 70 bytes, 71 with its sighash byte: low R, as
    /// every signer makes, and neither R nor S short. About one signature in 128 is short and is
    /// made again with fresh nonce data, so a transaction's weight is known before it is signed.
    fn sign_ecdsa_fixed_length(&self, message: &Message, key: &secp256k1_zkp::SecretKey) -> ecdsa::Signature {
        let mut signature = self.secp.sign_ecdsa_low_r(message, key);
        let mut counter = 0u32;

        while signature.serialize_der().len() != ECDSA_DER_LEN {
            counter += 1;

            let mut extra = [0u8; 32];
            extra[..4].copy_from_slice(&counter.to_le_bytes());
            signature = self.secp.sign_ecdsa_with_noncedata(message, key, &extra);
        }

        signature
    }

    /// The witness of a tapscript leaf spend: its items, the leaf script, the control block.
    fn tapscript_witness(
        &self,
        pst: &PartiallySignedTransaction,
        index: usize,
        tapscript: &TapscriptInput,
        derivation_path: Option<&DerivationPath>,
    ) -> Result<Vec<Vec<u8>>, SignerError> {
        let mut witness = Vec::with_capacity(tapscript.witness.len() + 2);

        for item in &tapscript.witness {
            witness.push(match item {
                TapscriptWitness::Bytes(bytes) => bytes.clone(),
                TapscriptWitness::Signature => self
                    .sign_tapscript(pst, index, &tapscript.script, &self.network, derivation_path)?
                    .serialize()
                    .to_vec(),
            });
        }

        witness.push(tapscript.script.to_bytes());
        witness.push(tapscript.control_block.serialize());

        Ok(witness)
    }

    #[allow(clippy::too_many_arguments)]
    fn get_signed_program_witness(
        &self,
        pst: &PartiallySignedTransaction,
        program: &dyn ProgramTrait,
        witness: &WitnessValues,
        witness_name: &str,
        sig_path: &[String],
        index: usize,
        derivation_path: Option<&DerivationPath>,
        message: &SigMessage,
    ) -> Result<WitnessValues, SignerError> {
        let signature = self.sign_program(pst, program, index, &self.network, derivation_path, message)?;

        // Inject the signature into the wtns name directly if the path is not provided
        let sig_val = if sig_path.is_empty() {
            Value::byte_array(signature.serialize())
        } else {
            let witness_types = program.get_witness_types()?;
            let witness_type = witness_types
                .get(&WitnessName::from_str_unchecked(witness_name))
                .ok_or(SignerError::WtnsFieldNotFound(witness_name.to_string()))?;

            let local_wtns = Arc::new(
                witness
                    .get(&WitnessName::from_str_unchecked(witness_name))
                    .expect("checked above")
                    .clone(),
            );

            WtnsInjector::inject_value(
                &local_wtns,
                witness_type,
                sig_path,
                Value::byte_array(signature.serialize()),
            )?
        };

        let mut hm = HashMap::new();

        witness.iter().for_each(|el| {
            hm.insert(el.0.clone(), el.1.clone());
        });

        hm.insert(WitnessName::from_str_unchecked(witness_name), sig_val);

        Ok(WitnessValues::from(hm))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn master_slip77(&self) -> Result<MasterBlindingKey, SignerError> {
        let seed = self.mnemonic.to_seed("");

        Ok(MasterBlindingKey::from_seed(&seed[..]))
    }

    fn derive_xpriv(&self, path: &DerivationPath) -> Result<Xpriv, SignerError> {
        Ok(self.xprv.derive_priv(&self.secp, &path)?)
    }

    fn master_xpriv(&self) -> Result<Xpriv, SignerError> {
        self.derive_xpriv(&DerivationPath::master())
    }

    fn derive_xpub(&self, path: &DerivationPath) -> Result<Xpub, SignerError> {
        let derived = self.derive_xpriv(path)?;

        Ok(Xpub::from_priv(&self.secp, &derived))
    }

    fn master_xpub(&self) -> Result<Xpub, SignerError> {
        self.derive_xpub(&DerivationPath::master())
    }

    fn fingerprint(&self) -> Result<Fingerprint, SignerError> {
        Ok(self.master_xpub()?.fingerprint())
    }

    fn get_slip77_descriptor(&self) -> Result<String, SignerError> {
        let wpkh_descriptor = self.get_wpkh_descriptor()?;
        let blinding_key = self.master_slip77()?;

        Ok(format!("ct(slip77({blinding_key}),{wpkh_descriptor})"))
    }

    fn get_wpkh_descriptor(&self) -> Result<String, SignerError> {
        let fingerprint = self.fingerprint()?;
        let path = self.get_derivation_path()?;
        let mut xpub = self.derive_xpub(&path)?;

        // TODO: Blockstream app does this. Is this a bug?
        xpub.parent_fingerprint = Fingerprint::default();

        Ok(format!("elwpkh([{fingerprint}/{path}]{xpub}/<0;1>/*)"))
    }

    fn get_derivation_path(&self) -> Result<DerivationPath, SignerError> {
        let coin_type = if self.network.is_mainnet() { 1776 } else { 1 };
        let path = format!("84h/{coin_type}h/0h");

        DerivationPath::from_str(&format!("m/{path}")).map_err(|e| SignerError::DerivationPath(e.to_string()))
    }

    fn get_contract_derivation_path(&self) -> Result<DerivationPath, SignerError> {
        let coin_type = if self.network.is_mainnet() { 1776 } else { 1 };
        let path = format!("{CONTRACT_KEY_PURPOSE}h/{coin_type}h/0h");

        DerivationPath::from_str(&format!("m/{path}")).map_err(|e| SignerError::DerivationPath(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::provider::EsploraProvider;
    use crate::utils::random_mnemonic;

    use super::*;

    /// A signer on the Sequentia testnet with an Esplora provider that is never called, valuing
    /// the policy asset at par.
    fn create_signer() -> Signer {
        let url = "http://127.0.0.1:1/api".to_string();
        let network = SimplicityNetwork::SequentiaTestnet;

        Signer::new(random_mnemonic().as_str(), Box::new(EsploraProvider::new(url, network)))
            .with_fee_exchange_rate(network.policy_asset(), FEE_EXCHANGE_RATE_SCALE)
    }

    fn confidential_input(signer: &Signer, value: u64) -> PartialInput {
        use simplicityhl::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
        use simplicityhl::elements::hashes::Hash;
        use simplicityhl::elements::{TxOut, TxOutSecrets};

        PartialInput::new(UTXO {
            outpoint: OutPoint::new(Txid::from_slice(&[0x01; 32]).unwrap(), 0),
            txout: TxOut::default(),
            secrets: Some(TxOutSecrets::new(
                signer.network.policy_asset(),
                AssetBlindingFactor::zero(),
                value,
                ValueBlindingFactor::zero(),
            )),
        })
    }

    #[test]
    fn explicit_change_target_cannot_balance_a_confidential_input() {
        let signer = create_signer();
        let mut ft = FinalTransaction::new();

        ft.add_input(confidential_input(&signer, 100_000), RequiredSignature::NativeEcdsa);
        ft.add_output(PartialOutput::new(
            signer.get_address().script_pubkey(),
            50_000,
            signer.network.policy_asset(),
        ));
        ft.add_change(ChangeOutput::new(signer.get_address().script_pubkey()));

        assert!(matches!(
            signer.estimate_fee(&ft, 1.0),
            Err(SignerError::ConfidentialInputWithoutBlindedOutput)
        ));
    }

    #[test]
    fn blinded_output_lets_the_explicit_change_target_stand() {
        let signer = create_signer();
        let mut ft = FinalTransaction::new();

        ft.add_input(confidential_input(&signer, 100_000), RequiredSignature::NativeEcdsa);
        ft.add_output(
            PartialOutput::new(
                signer.get_address().script_pubkey(),
                50_000,
                signer.network.policy_asset(),
            )
            .with_blinding_key(signer.get_blinding_public_key()),
        );
        ft.add_change(ChangeOutput::new(signer.get_address().script_pubkey()));

        assert!(!matches!(
            signer.estimate_fee(&ft, 1.0),
            Err(SignerError::ConfidentialInputWithoutBlindedOutput)
        ));
    }

    #[test]
    fn default_change_target_balances_it_by_itself() {
        let signer = create_signer();
        let mut ft = FinalTransaction::new();

        ft.add_input(confidential_input(&signer, 100_000), RequiredSignature::NativeEcdsa);
        ft.add_output(PartialOutput::new(
            signer.get_address().script_pubkey(),
            50_000,
            signer.network.policy_asset(),
        ));

        assert!(!matches!(
            signer.estimate_fee(&ft, 1.0),
            Err(SignerError::ConfidentialInputWithoutBlindedOutput)
        ));
    }

    #[test]
    fn fee_atoms_round_up_so_the_fee_is_never_valued_below_the_quote() {
        let asset = AssetId::from_slice(&[0x07; 32]).unwrap();
        let par = FeeAsset {
            asset,
            exchange_rate: FEE_EXCHANGE_RATE_SCALE,
        };
        let dear = FeeAsset {
            asset,
            exchange_rate: 3 * FEE_EXCHANGE_RATE_SCALE,
        };
        let cheap = FeeAsset {
            asset,
            exchange_rate: FEE_EXCHANGE_RATE_SCALE / 4,
        };

        assert_eq!(par.atoms(1_000), 1_000);
        // 1,000 / 3 = 333.33: 334 atoms are worth 1,002, 333 only 999
        assert_eq!(dear.atoms(1_000), 334);
        assert_eq!(cheap.atoms(1_000), 4_000);
    }

    #[test]
    fn the_dust_threshold_is_the_nodes_valued_in_the_fee_asset() {
        let asset = AssetId::from_slice(&[0x07; 32]).unwrap();
        let at = |exchange_rate| FeeAsset { asset, exchange_rate };
        let p2wpkh = Address::p2wpkh(
            &sequentia_signer().get_ecdsa_public_key(),
            None,
            SimplicityNetwork::SequentiaTestnet.address_params(),
        )
        .script_pubkey();
        let legacy = Address::p2pkh(
            &sequentia_signer().get_ecdsa_public_key(),
            None,
            SimplicityNetwork::SequentiaTestnet.address_params(),
        )
        .script_pubkey();

        // An explicit P2WPKH output is 66 bytes: 133 with its spend, 13.3 reference units at the
        // default dust relay fee, so 14.
        assert_eq!(at(FEE_EXCHANGE_RATE_SCALE).dust_threshold(&p2wpkh, DUST_RELAY_FEE), 14);
        // Worth a thousand reference units an atom: one atom.
        assert_eq!(
            at(1_000 * FEE_EXCHANGE_RATE_SCALE).dust_threshold(&p2wpkh, DUST_RELAY_FEE),
            1
        );
        // Worth a hundredth: 1,400 atoms.
        assert_eq!(
            at(FEE_EXCHANGE_RATE_SCALE / 100).dust_threshold(&p2wpkh, DUST_RELAY_FEE),
            1_400
        );
        // Not a witness program: 69 + 148 bytes, 21.7 reference units, so 22.
        assert_eq!(at(FEE_EXCHANGE_RATE_SCALE).dust_threshold(&legacy, DUST_RELAY_FEE), 22);
        // At Bitcoin's 3,000 per 1,000 vbytes: 399.
        assert_eq!(at(FEE_EXCHANGE_RATE_SCALE).dust_threshold(&p2wpkh, 3_000), 399);
    }

    #[test]
    fn change_below_the_threshold_joins_the_fee_and_only_below_it() {
        // The reviewer's probe B: an asset worth a thousand reference units an atom, a coin of
        // 1,000 and a payment of 990. The fee is one atom, the threshold one atom, so nine come
        // back as change.
        let gold = AssetId::from_slice(&[0x07; 32]).unwrap();
        let signer = sequentia_signer().with_fee_exchange_rate(gold, 1_000 * FEE_EXCHANGE_RATE_SCALE);
        let ft = gold_spend(&signer, gold, &[1_000], 990);
        let (tx, fee) = signer.finalize_strict(&ft, 100.0).unwrap();
        let amounts: Vec<u64> = tx.output.iter().map(|o| o.value.explicit().unwrap()).collect();

        assert_eq!(fee, 1);
        assert_eq!(amounts, vec![990, 9, 1]);

        // At par the threshold is 14 atoms: a surplus of 13 joins the fee, 14 is kept.
        let signer = sequentia_signer().with_fee_exchange_rate(gold, FEE_EXCHANGE_RATE_SCALE);
        let with_change = signer
            .estimate_spend(&gold_spend(&signer, gold, &[100_000], 50_000), 100.0)
            .unwrap();
        for (surplus, kept) in [(12, false), (13, false), (14, true), (15, true)] {
            let ft = gold_spend(&signer, gold, &[50_000 + with_change.fee + surplus], 50_000);
            let estimate = signer.estimate_spend(&ft, 100.0).unwrap();

            assert_eq!(estimate.change, kept, "surplus {surplus}");
            if kept {
                assert_eq!(estimate.fee, with_change.fee);
            } else {
                assert_eq!(estimate.fee, with_change.fee + surplus);
            }
        }

        // A node with another dust relay fee: at 3,000 the threshold at par is 399 atoms.
        let strict = sequentia_signer()
            .with_fee_exchange_rate(gold, FEE_EXCHANGE_RATE_SCALE)
            .with_dust_relay_fee(3_000);
        let ft = gold_spend(&strict, gold, &[50_000 + with_change.fee + 398], 50_000);
        assert!(!strict.estimate_spend(&ft, 100.0).unwrap().change);
        let ft = gold_spend(&strict, gold, &[50_000 + with_change.fee + 399], 50_000);
        assert!(strict.estimate_spend(&ft, 100.0).unwrap().change);
    }

    #[test]
    fn a_fixed_fee_network_pays_in_its_policy_asset_and_refuses_another() {
        let signer = Signer::from_mnemonic(random_mnemonic().as_str(), SimplicityNetwork::Liquid);
        let other = AssetId::from_slice(&[0x07; 32]).unwrap();
        let mut ft = FinalTransaction::new();
        ft.add_output(PartialOutput::new(Script::new(), 1, other));

        assert_eq!(signer.fee_asset_for(&ft).unwrap(), signer.network.policy_asset());
        assert_eq!(
            signer.fee_exchange_rate(signer.network.policy_asset()).unwrap(),
            FEE_EXCHANGE_RATE_SCALE
        );

        let signer = signer.with_fee_asset(other);
        assert!(matches!(
            signer.fee_asset_for(&ft),
            Err(SignerError::FeeAssetNotAccepted(asset)) if asset == other
        ));
    }

    #[test]
    fn a_configured_exchange_rate_is_used_and_a_zero_one_refused() {
        let asset = AssetId::from_slice(&[0x07; 32]).unwrap();
        let signer = sequentia_signer().with_fee_exchange_rate(asset, 42);

        assert_eq!(signer.fee_exchange_rate(asset).unwrap(), 42);

        let signer = signer.with_fee_exchange_rate(asset, 0);
        assert!(matches!(
            signer.fee_exchange_rate(asset),
            Err(SignerError::FeeAssetNotAccepted(_))
        ));
    }

    #[test]
    fn a_configured_exchange_rate_expires() {
        let asset = AssetId::from_slice(&[0x07; 32]).unwrap();
        let signer = sequentia_signer().with_fee_exchange_rate_for(asset, 42, Duration::from_millis(50));

        assert_eq!(signer.fee_exchange_rate(asset).unwrap(), 42);
        std::thread::sleep(Duration::from_millis(80));
        assert!(matches!(
            signer.fee_exchange_rate(asset),
            Err(SignerError::FeeExchangeRateExpired { asset: a, lifetime_secs: 0, .. }) if a == asset
        ));

        // Refused, not quietly replaced: a spend paying in the asset is refused with it.
        let ft = gold_spend(&signer, asset, &[100_000], 50_000);
        assert!(matches!(
            signer.finalize_strict(&ft, 100.0),
            Err(SignerError::FeeExchangeRateExpired { .. })
        ));

        // Set again, it is trusted again; the default lifetime is ten minutes.
        let signer = signer.with_fee_exchange_rate(asset, 42);
        assert_eq!(signer.fee_exchange_rate(asset).unwrap(), 42);
        assert_eq!(FEE_EXCHANGE_RATE_OVERRIDE_LIFETIME, Duration::from_mins(10));
    }

    #[test]
    fn an_esplora_provider_is_no_rate_source() {
        let asset = AssetId::from_slice(&[0x07; 32]).unwrap();
        let signer = Signer::new(
            random_mnemonic().as_str(),
            Box::new(EsploraProvider::new(
                "http://127.0.0.1:1/api".into(),
                SimplicityNetwork::SequentiaTestnet,
            )),
        );

        assert!(matches!(
            signer.fee_exchange_rate(asset),
            Err(SignerError::NoFeeExchangeRateSource(a)) if a == asset
        ));
    }

    #[test]
    fn contract_keys_are_not_wallet_keys() {
        let signer = sequentia_signer();
        let secp = Secp256k1::new();
        let wallet = |path: &str| {
            let key = signer.get_private_key_at(Some(&DerivationPath::from_str(path).unwrap()));
            Keypair::from_secret_key(&secp, &key.inner).x_only_public_key().0
        };

        // The default contract key, at 0/0 under m/8383h/1h/0h, is none of the wallet's funding
        // or change keys, and none of the paths the wallet kit uses beside them.
        let contract = signer.get_schnorr_public_key();
        assert_eq!(contract, signer.get_contract_public_key_at(None));
        for path in ["0/0", "0/1", "1/0", "1/1", "2/0", "3/0", "4/0"] {
            assert_ne!(contract, wallet(path), "{path}");
        }
        assert_ne!(contract, signer.get_ecdsa_public_key().inner.x_only_public_key().0);

        let expected = {
            let seed = signer.mnemonic.to_seed("");
            let master = Xpriv::new_master(SimplicityNetwork::SequentiaTestnet, &seed).unwrap();
            let path = DerivationPath::from_str("m/8383h/1h/0h/0/0").unwrap();
            let key = master.derive_priv(&secp, &path).unwrap().private_key;
            Keypair::from_secret_key(&secp, &key).x_only_public_key().0
        };
        assert_eq!(contract, expected);

        // A relative path moves within the contract account.
        let other = signer.get_contract_public_key_at(Some(&DerivationPath::from_str("0/7").unwrap()));
        assert_ne!(other, contract);
        assert_ne!(other, wallet("0/7"));
    }

    #[test]
    fn a_custom_message_is_signed_only_for_a_program_that_declares_it() {
        use crate::program::{ArgumentsTrait, Program};
        use simplicityhl::Arguments;
        use simplicityhl::elements::pset::Input;

        #[derive(Clone)]
        struct NoArguments;
        impl ArgumentsTrait for NoArguments {
            fn build_arguments(&self) -> Arguments {
                Arguments::default()
            }
        }

        let signer = sequentia_signer();
        let network = SimplicityNetwork::SequentiaTestnet;
        let program = Program::new("fn main() { assert!(jet::eq_8(1, 1)); }", &NoArguments);
        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_input(Input {
            witness_utxo: Some(TxOut::new_fee(1_000, network.policy_asset())),
            ..Default::default()
        });
        pst.inputs_mut()[0].witness_utxo.as_mut().unwrap().script_pubkey = program.get_script_pubkey(&network);
        let custom = SigMessage::Custom(Arc::new(|_| [0x11; 32]));

        assert!(matches!(
            signer.sign_program(&pst, &program, 0, &network, None, &custom),
            Err(SignerError::CustomSigMessageUndeclared(0))
        ));
        assert!(
            signer
                .sign_program(&pst, &program, 0, &network, None, &SigMessage::Sighash)
                .is_ok()
        );

        let declared = program.with_custom_sig_message();
        let signature = signer
            .sign_program(&pst, &declared, 0, &network, None, &custom)
            .unwrap();
        let message = Message::from_digest([0x11; 32]);
        assert!(
            signer
                .secp
                .verify_schnorr(&signature, &message, &signer.get_schnorr_public_key())
                .is_ok()
        );
    }

    fn sequentia_signer() -> Signer {
        Signer::from_mnemonic(random_mnemonic().as_str(), SimplicityNetwork::SequentiaTestnet)
    }

    #[test]
    fn on_sequentia_the_fee_is_paid_in_the_one_asset_moved() {
        let signer = sequentia_signer();
        let gold = AssetId::from_slice(&[0x07; 32]).unwrap();
        let mut ft = FinalTransaction::new();
        ft.add_output(PartialOutput::new(Script::new(), 1, gold));

        assert_eq!(signer.fee_asset_for(&ft).unwrap(), gold);
    }

    #[test]
    fn on_sequentia_nothing_falls_back_to_the_policy_asset() {
        let signer = sequentia_signer();
        let gold = AssetId::from_slice(&[0x07; 32]).unwrap();
        let silver = AssetId::from_slice(&[0x08; 32]).unwrap();

        // Two assets moved and none named: refused, policy asset included.
        let mut ft = FinalTransaction::new();
        ft.add_output(PartialOutput::new(Script::new(), 1, gold));
        ft.add_output(PartialOutput::new(Script::new(), 1, silver));
        assert!(matches!(signer.fee_asset_for(&ft), Err(SignerError::FeeAssetUnset(_))));

        // Nothing moved and none named: refused as well.
        assert!(matches!(
            signer.fee_asset_for(&FinalTransaction::new()),
            Err(SignerError::FeeAssetUnset(_))
        ));

        // Naming one settles it.
        let signer = signer.with_fee_asset(silver);
        assert_eq!(signer.fee_asset_for(&ft).unwrap(), silver);

        // With no provider and no configured rate, even the policy asset has no rate.
        assert!(matches!(
            signer.fee_exchange_rate(SimplicityNetwork::SequentiaTestnet.policy_asset()),
            Err(SignerError::NoFeeExchangeRateSource(_))
        ));
    }

    #[test]
    fn on_sequentia_a_send_names_its_asset() {
        let signer = sequentia_signer();

        assert!(matches!(signer.send(Script::new(), 1), Err(SignerError::AssetUnnamed)));
    }

    #[test]
    fn on_sequentia_change_is_explicit_and_paid_in_the_fee_asset() {
        let gold = AssetId::from_slice(&[0x07; 32]).unwrap();
        let signer = sequentia_signer().with_fee_exchange_rate(gold, FEE_EXCHANGE_RATE_SCALE * 2);
        let mut ft = FinalTransaction::new();

        ft.add_input(
            PartialInput::new(UTXO {
                outpoint: OutPoint::new(Txid::from_slice(&[0x01; 32]).unwrap(), 0),
                txout: simplicityhl::elements::TxOut::new_fee(100_000, gold),
                secrets: None,
            }),
            RequiredSignature::NativeEcdsa,
        );
        ft.add_output(PartialOutput::new(signer.get_address().script_pubkey(), 50_000, gold));

        let (tx, fee) = signer.finalize_strict(&ft, 1_000.0).unwrap();

        // At twice par, a fee of `vsize` reference units costs half as many atoms.
        assert_eq!(fee, (tx.vsize() as u64).div_ceil(2));
        for output in &tx.output {
            assert!(output.asset.is_explicit() && output.value.is_explicit());
            assert_eq!(output.asset.explicit(), Some(gold));
        }
        let change = tx
            .output
            .iter()
            .find(|o| o.value.explicit() == Some(50_000 - fee))
            .unwrap();
        assert_eq!(change.script_pubkey, signer.get_address().script_pubkey());
    }

    #[test]
    fn every_ecdsa_signature_is_71_bytes_with_its_sighash_byte() {
        let signer = sequentia_signer();
        let key = signer.get_private_key().inner;

        for n in 0u32..512 {
            let mut digest = [0u8; 32];
            digest[..4].copy_from_slice(&n.to_le_bytes());
            let signature = signer.sign_ecdsa_fixed_length(&Message::from_digest(digest), &key);

            assert_eq!(signature.serialize_der().len(), ECDSA_DER_LEN);
            assert_eq!(elementssig_to_rawsig(&(signature, EcdsaSighashType::All)).len(), 71);
            assert!(
                signer
                    .secp
                    .verify_ecdsa(
                        &Message::from_digest(digest),
                        &signature,
                        &signer.get_ecdsa_public_key().inner
                    )
                    .is_ok()
            );
        }
    }

    fn gold_spend(signer: &Signer, gold: AssetId, inputs: &[u64], pay: u64) -> FinalTransaction {
        let mut ft = FinalTransaction::new();

        for (n, value) in inputs.iter().enumerate() {
            ft.add_input(
                PartialInput::new(UTXO {
                    outpoint: OutPoint::new(Txid::from_slice(&[0x01; 32]).unwrap(), u32::try_from(n).unwrap()),
                    txout: simplicityhl::elements::TxOut::new_fee(*value, gold),
                    secrets: None,
                }),
                RequiredSignature::NativeEcdsa,
            );
        }
        ft.add_output(PartialOutput::new(signer.get_address().script_pubkey(), pay, gold));

        ft
    }

    #[test]
    fn the_estimate_is_the_weight_and_fee_of_the_signed_transaction() {
        let gold = AssetId::from_slice(&[0x07; 32]).unwrap();
        let signer = sequentia_signer().with_fee_exchange_rate(gold, FEE_EXCHANGE_RATE_SCALE * 3);

        for inputs in [vec![100_000], vec![40_000, 30_000, 30_000]] {
            for rate in [100.0, 1_000.0, 25_000.0] {
                let ft = gold_spend(&signer, gold, &inputs, 50_000);
                let estimate = signer.estimate_spend(&ft, rate).unwrap();
                let (tx, fee) = signer.finalize_strict(&ft, rate).unwrap();

                assert_eq!(estimate.weight, tx.weight());
                assert_eq!(estimate.vsize, tx.vsize());
                assert_eq!(estimate.fee, fee);
                assert_eq!(estimate.fee_asset, gold);
                assert!(estimate.change);
                assert_eq!(estimate.budgets, Vec::new());
                // In the fee asset's own atoms: a third of the reference fee, rounded up.
                assert_eq!(
                    fee,
                    FinalTransaction::new().calculate_fee(tx.weight(), rate).div_ceil(3)
                );
            }
        }
    }

    #[test]
    fn without_room_for_change_the_whole_remainder_is_the_fee() {
        let gold = AssetId::from_slice(&[0x07; 32]).unwrap();
        let signer = sequentia_signer().with_fee_exchange_rate(gold, FEE_EXCHANGE_RATE_SCALE);
        // With change, the fee is about one atom per vbyte; leave less than that plus the
        // smallest change the node relays.
        let with_change = signer
            .estimate_spend(&gold_spend(&signer, gold, &[100_000], 50_000), 1_000.0)
            .unwrap();
        let dust = FeeAsset {
            asset: gold,
            exchange_rate: FEE_EXCHANGE_RATE_SCALE,
        }
        .dust_threshold(&signer.get_address().script_pubkey(), DUST_RELAY_FEE);
        assert_eq!(dust, 14);
        let input = 50_000 + with_change.fee + dust - 1;
        let ft = gold_spend(&signer, gold, &[input], 50_000);

        let estimate = signer.estimate_spend(&ft, 1_000.0).unwrap();
        let (tx, fee) = signer.finalize_strict(&ft, 1_000.0).unwrap();

        assert!(!estimate.change);
        assert!(estimate.weight < with_change.weight);
        assert_eq!(estimate.weight, tx.weight());
        assert_eq!(estimate.fee, input - 50_000);
        assert_eq!(fee, input - 50_000);
        assert_eq!(tx.output.len(), 2);
    }

    #[test]
    fn keys_correspond_to_address() {
        let signer = create_signer();

        let address = signer.get_address();
        let pubkey = signer.get_ecdsa_public_key();

        let derived_addr = Address::p2wpkh(
            &pubkey,
            None,
            signer.get_provider().unwrap().get_network().address_params(),
        );

        assert_eq!(derived_addr.to_string(), address.to_string());
    }

    #[test]
    fn descriptors() {
        let signer = create_signer();

        println!("{}", signer.get_address());
        println!("{}", signer.get_confidential_address());
    }
}
