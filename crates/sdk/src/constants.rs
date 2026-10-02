/// General public blinder key to use
pub const PUBLIC_SECRET_BLINDER_KEY: [u8; 32] = [1; 32];
/// Dummy signature, which is used for fee estimation
pub const DUMMY_SIGNATURE: [u8; 64] = [1; 64];

/// The node's default dust relay fee (`-dustrelayfee`, `DUST_RELAY_TX_FEE`), in reference units
/// per 1,000 vbytes. An explicit output is dust when spending it would cost more than it is worth
/// at this rate; see [`crate::signer::FeeAsset::dust_threshold`]. The node takes the setting only
/// as a debug option and reports it over no RPC, so the signer assumes the default unless told
/// otherwise with [`crate::signer::Signer::with_dust_relay_fee`].
pub const DUST_RELAY_FEE: u64 = 100;

/// How long an exchange rate set with [`crate::signer::Signer::with_fee_exchange_rate`] is
/// trusted: ten minutes, about ten blocks at Sequentia's 60-second spacing. A node's rates move
/// with its price server, so a rate typed in by hand is refused once it is older than this rather
/// than used to underpay a fee the node then refuses. A provider that reads the node's table
/// ([`crate::provider::RpcProvider`]) asks it afresh at every quote.
pub const FEE_EXCHANGE_RATE_OVERRIDE_LIFETIME: std::time::Duration = std::time::Duration::from_mins(10);

/// The BIP 43 purpose under which the signer derives the keys that sign for contracts: Simplicity
/// programs and tapscript leaves. The account is `m/8383h/{coin}h/0h`, apart from the wallet's
/// `m/84h/{coin}h/0h`, whose `0/i` and `1/i` keys hold its funding and change: a signature by a
/// contract key never answers for a wallet coin, nor a wallet key for a contract. 8383 is no
/// purpose a wallet scans for funds.
pub const CONTRACT_KEY_PURPOSE: u32 = 8383;

/// The scale of a fee exchange rate: a fee asset whose rate equals this is valued at par
/// with the unit fee rates are quoted in. A fee of `f` reference units is paid with
/// `ceil(f * FEE_EXCHANGE_RATE_SCALE / rate)` atoms of the fee asset.
pub const FEE_EXCHANGE_RATE_SCALE: u64 = 100_000_000;

/// Policy `AssetId` (hex, BE) for Liquid mainnet.
pub const LIQUID_POLICY_ASSET_STR: &str = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

/// Policy `AssetId` (hex, BE) for Liquid testnet.
pub const LIQUID_TESTNET_POLICY_ASSET_STR: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

/// Policy `AssetId` (hex, BE) for Elements regtest.
pub const LIQUID_DEFAULT_REGTEST_ASSET_STR: &str = "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225";

/// Example test `AssetId` (hex, BE) on Liquid testnet.
pub const LIQUID_TESTNET_TEST_ASSET_ID_STR: &str = "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5";

/// Policy `AssetId` (hex, BE) of the Sequentia testnet: the Sequence token, one fee asset
/// among any the node accepts.
pub const SEQUENTIA_TESTNET_POLICY_ASSET_STR: &str = "c8eccacf0953e1931cd31e434d8319101cc36e6c38b0e2104d8687552fae3e40";

/// Genesis block hash (hex, display order) of the Sequentia testnet.
pub const SEQUENTIA_TESTNET_GENESIS_STR: &str = "ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e";
