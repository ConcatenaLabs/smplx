use std::str::FromStr;

use simplicityhl::simplicity::elements;
use simplicityhl::simplicity::hashes::{Hash, sha256};

use elements_miniscript::bitcoin::NetworkKind;

use crate::program::BudgetRule;

use crate::constants::{
    LIQUID_DEFAULT_REGTEST_ASSET_STR, LIQUID_POLICY_ASSET_STR, LIQUID_TESTNET_POLICY_ASSET_STR,
    SEQUENTIA_TESTNET_GENESIS_STR, SEQUENTIA_TESTNET_POLICY_ASSET_STR,
};

/// The default Bitcoin `AssetId` used on Liquid testnet.
pub static LIQUID_TESTNET_BITCOIN_ASSET: std::sync::LazyLock<elements::AssetId> = std::sync::LazyLock::new(|| {
    elements::AssetId::from_inner(sha256::Midstate([
        0x49, 0x9a, 0x81, 0x85, 0x45, 0xf6, 0xba, 0xe3, 0x9f, 0xc0, 0x3b, 0x63, 0x7f, 0x2a, 0x4e, 0x1e, 0x64, 0xe5,
        0x90, 0xca, 0xc1, 0xbc, 0x3a, 0x6f, 0x6d, 0x71, 0xaa, 0x44, 0x43, 0x65, 0x4c, 0x14,
    ]))
});

/// The genesis block hash for Liquid mainnet.
pub static LIQUID_MAINNET_GENESIS: std::sync::LazyLock<elements::BlockHash> = std::sync::LazyLock::new(|| {
    elements::BlockHash::from_byte_array([
        0x03, 0x60, 0x20, 0x8a, 0x88, 0x96, 0x92, 0x37, 0x2c, 0x8d, 0x68, 0xb0, 0x84, 0xa6, 0x2e, 0xfd, 0xf6, 0x0e,
        0xa1, 0xa3, 0x59, 0xa0, 0x4c, 0x94, 0xb2, 0x0d, 0x22, 0x36, 0x58, 0x27, 0x66, 0x14,
    ])
});

/// The genesis block hash for Liquid testnet.
pub static LIQUID_TESTNET_GENESIS: std::sync::LazyLock<elements::BlockHash> = std::sync::LazyLock::new(|| {
    elements::BlockHash::from_byte_array([
        0xc1, 0xb1, 0x6a, 0xe2, 0x4f, 0x24, 0x23, 0xae, 0xa2, 0xea, 0x34, 0x55, 0x22, 0x92, 0x79, 0x3b, 0x5b, 0x5e,
        0x82, 0x99, 0x9a, 0x1e, 0xed, 0x81, 0xd5, 0x6a, 0xee, 0x52, 0x8e, 0xda, 0x71, 0xa7,
    ])
});

/// The genesis block hash for Elements regtest environments.
pub static LIQUID_REGTEST_GENESIS: std::sync::LazyLock<elements::BlockHash> = std::sync::LazyLock::new(|| {
    elements::BlockHash::from_byte_array([
        0x21, 0xca, 0xb1, 0xe5, 0xda, 0x47, 0x18, 0xea, 0x14, 0x0d, 0x97, 0x16, 0x93, 0x17, 0x02, 0x42, 0x2f, 0x0e,
        0x6a, 0xd9, 0x15, 0xc8, 0xd9, 0xb5, 0x83, 0xca, 0xc2, 0x70, 0x6b, 0x2a, 0x90, 0x00,
    ])
});

/// Sequentia's Simplicity budget: four weight units per witness byte
/// (`SIMPLICITY_BUDGET_PER_WITNESS_BYTE` in the node), and an annex of up to 100,000 bytes relays
/// on a Simplicity leaf (`MAX_STANDARD_SIMPLICITY_ANNEX_SIZE`).
pub const SEQUENTIA_SIMPLICITY_BUDGET: BudgetRule = BudgetRule {
    per_witness_byte: 4,
    max_standard_annex: 100_000,
};

/// Represents the target network configuration for Simplicity interactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SimplicityNetwork {
    /// Liquid mainnet.
    Liquid,
    /// Liquid testnet.
    LiquidTestnet,
    /// Local Elements Regtest environment.
    ElementsRegtest {
        /// Regtest mode `AssetId`, which is used as a default policy asset locally.
        policy_asset: elements::AssetId,
    },
    /// Custom Elements environment whose genesis is derived from its chain parameters.
    ElementsCustom {
        /// Custom network policy asset.
        policy_asset: elements::AssetId,
        /// Custom network genesis block hash.
        genesis_hash: elements::BlockHash,
    },
    /// The Sequentia testnet (`-chain=test`).
    SequentiaTestnet,
    /// A local Sequentia chain: a custom chain such as `elementsregtest`, whose genesis and
    /// policy asset are read from its node.
    SequentiaRegtest {
        /// The chain's policy asset. On Sequentia it is one fee asset among any the node accepts.
        policy_asset: elements::AssetId,
        /// The chain's genesis block hash.
        genesis_hash: elements::BlockHash,
    },
}

impl SimplicityNetwork {
    /// Creates a default Elements Regtest configuration.
    ///
    /// # Panics
    /// This function will panic if the provided `LIQUID_DEFAULT_REGTEST_ASSET_STR` cannot be parsed.
    #[must_use]
    pub fn default_regtest() -> Self {
        let policy_asset = elements::AssetId::from_str(LIQUID_DEFAULT_REGTEST_ASSET_STR).unwrap();
        Self::ElementsRegtest { policy_asset }
    }

    /// Returns the policy `AssetId` associated with the current network.
    ///
    /// # Panics
    /// This function will panic if the provided `LIQUID_DEFAULT_REGTEST_ASSET_STR` cannot be parsed.
    #[must_use]
    pub fn policy_asset(&self) -> elements::AssetId {
        match self {
            Self::Liquid => elements::AssetId::from_str(LIQUID_POLICY_ASSET_STR).unwrap(),
            Self::LiquidTestnet => elements::AssetId::from_str(LIQUID_TESTNET_POLICY_ASSET_STR).unwrap(),
            Self::SequentiaTestnet => elements::AssetId::from_str(SEQUENTIA_TESTNET_POLICY_ASSET_STR).unwrap(),
            Self::ElementsRegtest { policy_asset }
            | Self::ElementsCustom { policy_asset, .. }
            | Self::SequentiaRegtest { policy_asset, .. } => *policy_asset,
        }
    }

    /// Returns the genesis block hash for the network variant.
    ///
    /// # Panics
    /// This function will panic if a built-in genesis hash constant cannot be parsed.
    #[must_use]
    pub fn genesis_block_hash(&self) -> elements::BlockHash {
        match self {
            Self::Liquid => *LIQUID_MAINNET_GENESIS,
            Self::LiquidTestnet => *LIQUID_TESTNET_GENESIS,
            Self::ElementsRegtest { .. } => *LIQUID_REGTEST_GENESIS,
            Self::SequentiaTestnet => elements::BlockHash::from_str(SEQUENTIA_TESTNET_GENESIS_STR).unwrap(),
            Self::ElementsCustom { genesis_hash, .. } | Self::SequentiaRegtest { genesis_hash, .. } => *genesis_hash,
        }
    }

    /// Determines if the current network is the mainnet (Liquid).
    #[must_use]
    pub fn is_mainnet(&self) -> bool {
        self == &Self::Liquid
    }

    /// Whether consensus on this network accepts fees only in its policy asset.
    ///
    /// Where it does, the signer pays every fee in the policy asset. Where it does not, the
    /// signer pays in the asset it is told to, or in the one asset a transaction moves, and
    /// never falls back to the policy asset.
    #[must_use]
    pub fn fee_asset_is_fixed(&self) -> bool {
        match self {
            Self::Liquid | Self::LiquidTestnet | Self::ElementsRegtest { .. } | Self::ElementsCustom { .. } => true,
            Self::SequentiaTestnet | Self::SequentiaRegtest { .. } => false,
        }
    }

    /// Whether the signer's default change output is confidential on this network.
    ///
    /// Where it is not, change is explicit unless the transaction spends a confidential input
    /// and has no other blinded output, in which case the change is blinded because the
    /// transaction cannot balance otherwise.
    #[must_use]
    pub fn confidential_change_by_default(&self) -> bool {
        match self {
            Self::Liquid | Self::LiquidTestnet | Self::ElementsRegtest { .. } | Self::ElementsCustom { .. } => true,
            Self::SequentiaTestnet | Self::SequentiaRegtest { .. } => false,
        }
    }

    /// Whether this network's nodes charge a confidential transaction's fee on its discounted
    /// weight. A Sequentia node does not unless started with `-acceptdiscountct=1`, so the signer
    /// charges the full weight there.
    #[must_use]
    pub fn discounted_ct_fees(&self) -> bool {
        match self {
            Self::Liquid | Self::LiquidTestnet | Self::ElementsRegtest { .. } | Self::ElementsCustom { .. } => true,
            Self::SequentiaTestnet | Self::SequentiaRegtest { .. } => false,
        }
    }

    /// How this network turns a Simplicity spend's witness into execution budget, and the
    /// largest annex it relays to raise it.
    #[must_use]
    pub fn simplicity_budget(&self) -> BudgetRule {
        match self {
            Self::Liquid | Self::LiquidTestnet | Self::ElementsRegtest { .. } | Self::ElementsCustom { .. } => {
                BudgetRule::ELEMENTS
            }
            Self::SequentiaTestnet | Self::SequentiaRegtest { .. } => SEQUENTIA_SIMPLICITY_BUDGET,
        }
    }

    /// Returns the address parameters associated with the current enum variant.
    #[must_use]
    pub const fn address_params(&self) -> &'static elements::AddressParams {
        match self {
            Self::Liquid => &elements::AddressParams::LIQUID,
            Self::LiquidTestnet => &elements::AddressParams::LIQUID_TESTNET,
            Self::SequentiaTestnet => &elements::AddressParams::SEQUENTIA_TESTNET,
            Self::ElementsRegtest { .. } | Self::ElementsCustom { .. } | Self::SequentiaRegtest { .. } => {
                &elements::AddressParams::ELEMENTS
            }
        }
    }
}

impl From<SimplicityNetwork> for NetworkKind {
    fn from(value: SimplicityNetwork) -> Self {
        (&value).into()
    }
}

impl From<&SimplicityNetwork> for NetworkKind {
    fn from(value: &SimplicityNetwork) -> Self {
        if value.is_mainnet() {
            NetworkKind::Main
        } else {
            NetworkKind::Test
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_networks_expose_policy_and_address_metadata() {
        let liquid = SimplicityNetwork::Liquid;
        let testnet = SimplicityNetwork::LiquidTestnet;
        let regtest = SimplicityNetwork::default_regtest();

        assert!(liquid.is_mainnet());
        assert!(!testnet.is_mainnet());
        assert!(!regtest.is_mainnet());

        for (network, asset, genesis, params) in [
            (
                liquid,
                "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
                "1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003",
                &elements::AddressParams::LIQUID,
            ),
            (
                testnet,
                "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
                "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1",
                &elements::AddressParams::LIQUID_TESTNET,
            ),
            (
                regtest,
                "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
                "00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21",
                &elements::AddressParams::ELEMENTS,
            ),
        ] {
            assert_eq!(network.policy_asset().to_string(), asset);
            assert_eq!(network.genesis_block_hash().to_string(), genesis);
            assert_eq!(network.address_params(), params);
        }

        assert_eq!(NetworkKind::from(liquid), NetworkKind::Main);

        let sequentia = SimplicityNetwork::SequentiaTestnet;
        assert!(!sequentia.is_mainnet());
        assert!(!sequentia.fee_asset_is_fixed());
        assert!(!sequentia.confidential_change_by_default());
        assert_eq!(
            sequentia.policy_asset().to_string(),
            "c8eccacf0953e1931cd31e434d8319101cc36e6c38b0e2104d8687552fae3e40"
        );
        assert_eq!(
            sequentia.genesis_block_hash().to_string(),
            "ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e"
        );
        assert_eq!(sequentia.address_params().bech_hrp.as_str(), "tb");
        assert_eq!(sequentia.address_params().blech_hrp.as_str(), "tsqb");
        assert_eq!(sequentia.simplicity_budget(), SEQUENTIA_SIMPLICITY_BUDGET);
        assert_eq!(liquid.simplicity_budget(), BudgetRule::ELEMENTS);
        assert_eq!(NetworkKind::from(&testnet), NetworkKind::Test);
        assert_eq!(NetworkKind::from(regtest), NetworkKind::Test);
    }
}
