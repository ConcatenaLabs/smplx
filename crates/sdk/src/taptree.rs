//! Taproot trees with several leaves.
//!
//! A contract output is a taproot output whose tree may hold several leaves: Simplicity programs
//! (leaf version `0xbe`), tapscripts (leaf version `0xc4`), and hidden nodes such as a data leaf
//! that commits to a program's parameters. [`TapTree`] describes the shape; [`ContractTree`] fixes
//! it under an internal key and derives the output key, the address, and each leaf's control
//! block. A spend names the leaf it takes.

use std::collections::BTreeSet;
use std::sync::Arc;

use simplicityhl::elements::secp256k1_zkp::XOnlyPublicKey;
use simplicityhl::elements::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use simplicityhl::elements::{Address, Script};
use simplicityhl::simplicity::bitcoin::secp256k1;
use simplicityhl::simplicity::hashes::{Hash, sha256};
use simplicityhl::simplicity::leaf_version;

use crate::program::{Program, ProgramError};
use crate::provider::SimplicityNetwork;
use crate::transaction::{TapscriptInput, TapscriptWitness};
use crate::utils::{tap_data_hash, tr_unspendable_key};

/// Errors raised while building a tree or looking up one of its leaves.
#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    /// Two leaves carry the same name, so a spend could not say which one it takes.
    #[error("Two leaves are named {0:?}")]
    DuplicateName(String),

    /// Two leaves commit to the same script at the same version, so they share a control block
    /// lookup and a spend could not say which one it takes.
    #[error("Leaves {0:?} and {1:?} are the same script at the same leaf version")]
    DuplicateLeaf(String, String),

    /// A program in a tree carries its own storage slots. Its data leaves belong in the tree.
    #[error("Program {0:?} has storage slots; put its data leaves in the tree instead")]
    ProgramHasStorage(String),

    /// No leaf has this name.
    #[error("No leaf is named {0:?}")]
    UnknownLeaf(String),

    /// The named leaf is not a Simplicity program.
    #[error("Leaf {0:?} is not a Simplicity program")]
    NotSimplicity(String),

    /// The named leaf is not a tapscript.
    #[error("Leaf {0:?} is not a tapscript")]
    NotTapscript(String),

    /// The tree is deeper than taproot allows.
    #[error("The tree is deeper than taproot allows: {0}")]
    Depth(String),

    /// A program in the tree did not compile.
    #[error(transparent)]
    Program(#[from] ProgramError),
}

/// The shape of a taproot tree: leaves and the branches that join them.
#[derive(Clone)]
pub enum TapTree {
    /// A Simplicity program, committed to by its commitment root at leaf version `0xbe`.
    Simplicity {
        /// The name a spend uses for this leaf.
        name: String,
        /// The program.
        program: Program,
    },
    /// A tapscript at leaf version `0xc4`.
    Tapscript {
        /// The name a spend uses for this leaf.
        name: String,
        /// The script.
        script: Script,
    },
    /// A node known only by its hash: a data leaf, or a subtree that is never revealed.
    Hidden(sha256::Hash),
    /// A branch joining two subtrees.
    Branch(Box<TapTree>, Box<TapTree>),
}

impl TapTree {
    /// A Simplicity leaf.
    pub fn simplicity(name: impl Into<String>, program: Program) -> Self {
        Self::Simplicity {
            name: name.into(),
            program,
        }
    }

    /// A tapscript leaf.
    pub fn tapscript(name: impl Into<String>, script: Script) -> Self {
        Self::Tapscript {
            name: name.into(),
            script,
        }
    }

    /// A data leaf: the hidden node `tagged("TapData", bytes)`, which a program reads back with
    /// `jet::tappath` and checks against the parameters it is given.
    #[must_use]
    pub fn data(bytes: &[u8]) -> Self {
        Self::Hidden(tap_data_hash(bytes))
    }

    /// A hidden node with the given hash.
    #[must_use]
    pub fn hidden(hash: sha256::Hash) -> Self {
        Self::Hidden(hash)
    }

    /// A branch joining `left` and `right`. Taproot sorts a branch's two hashes, so the order the
    /// children are given in does not change the output; it fixes only the order of traversal.
    #[must_use]
    pub fn branch(left: TapTree, right: TapTree) -> Self {
        Self::Branch(Box::new(left), Box::new(right))
    }

    /// Visits every leaf and hidden node depth-first, left before right, with its depth.
    fn visit<'a>(&'a self, depth: usize, f: &mut dyn FnMut(&'a TapTree, usize)) {
        match self {
            Self::Branch(left, right) => {
                left.visit(depth + 1, f);
                right.visit(depth + 1, f);
            }
            leaf => f(leaf, depth),
        }
    }
}

/// A spendable leaf of a [`ContractTree`]: its script and leaf version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeLeaf {
    /// The leaf's name.
    pub name: String,
    /// The leaf script: a tapscript, or a Simplicity program's 32-byte commitment root.
    pub script: Script,
    /// The leaf version: `0xc4` for a tapscript, `0xbe` for Simplicity.
    pub version: LeafVersion,
}

impl TreeLeaf {
    /// The leaf's tapleaf hash.
    #[must_use]
    pub fn leaf_hash(&self) -> TapLeafHash {
        TapLeafHash::from_script(&self.script, self.version)
    }
}

/// A taproot tree fixed under an internal key: the output a contract is paid to.
#[derive(Clone)]
pub struct ContractTree {
    root: TapTree,
    leaves: Vec<TreeLeaf>,
    info: Arc<TaprootSpendInfo>,
}

impl ContractTree {
    /// Fixes `root` under `internal_key`.
    ///
    /// # Errors
    /// Returns a `TreeError` when two leaves share a name or a script, when a program carries its
    /// own storage slots or does not compile, or when the tree is too deep.
    pub fn new(internal_key: XOnlyPublicKey, root: TapTree) -> Result<Self, TreeError> {
        let mut nodes = Vec::new();
        root.visit(0, &mut |node, depth| nodes.push((node, depth)));

        let mut names = BTreeSet::new();
        let mut leaves: Vec<TreeLeaf> = Vec::new();
        let mut builder = TaprootBuilder::new();

        for (node, depth) in nodes {
            let leaf = match node {
                TapTree::Simplicity { name, program } => {
                    if program.get_storage_len() > 0 {
                        return Err(TreeError::ProgramHasStorage(name.clone()));
                    }

                    TreeLeaf {
                        name: name.clone(),
                        script: Script::from(program.try_cmr()?.to_vec()),
                        version: leaf_version(),
                    }
                }
                TapTree::Tapscript { name, script } => TreeLeaf {
                    name: name.clone(),
                    script: script.clone(),
                    version: LeafVersion::default(),
                },
                TapTree::Hidden(hash) => {
                    builder = builder
                        .add_hidden(depth, *hash)
                        .map_err(|e| TreeError::Depth(e.to_string()))?;
                    continue;
                }
                TapTree::Branch(..) => unreachable!("visit yields only leaves and hidden nodes"),
            };

            if !names.insert(leaf.name.clone()) {
                return Err(TreeError::DuplicateName(leaf.name));
            }

            if let Some(other) = leaves
                .iter()
                .find(|other| other.script == leaf.script && other.version == leaf.version)
            {
                return Err(TreeError::DuplicateLeaf(other.name.clone(), leaf.name));
            }

            builder = builder
                .add_leaf_with_ver(depth, leaf.script.clone(), leaf.version)
                .map_err(|e| TreeError::Depth(e.to_string()))?;
            leaves.push(leaf);
        }

        let info = builder
            .finalize(secp256k1::SECP256K1, internal_key)
            .map_err(|e| TreeError::Depth(e.to_string()))?;

        Ok(Self {
            root,
            leaves,
            info: Arc::new(info),
        })
    }

    /// Fixes `root` under the internal key with no known discrete logarithm, so the output has no
    /// key path and is spent only through its leaves.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn script_only(root: TapTree) -> Result<Self, TreeError> {
        Self::new(tr_unspendable_key(), root)
    }

    /// The tree's shape.
    #[must_use]
    pub fn root(&self) -> &TapTree {
        &self.root
    }

    /// The spendable leaves, depth-first, left before right.
    #[must_use]
    pub fn leaves(&self) -> &[TreeLeaf] {
        &self.leaves
    }

    /// The taproot spending data: internal key, Merkle root, output key and every leaf's path.
    #[must_use]
    pub fn spend_info(&self) -> &TaprootSpendInfo {
        &self.info
    }

    /// The output key's x coordinate.
    #[must_use]
    pub fn output_key(&self) -> XOnlyPublicKey {
        self.info.output_key().into_inner()
    }

    /// The output script: `OP_1 <output key>`.
    #[must_use]
    pub fn script_pubkey(&self) -> Script {
        Script::new_v1_p2tr_tweaked(self.info.output_key())
    }

    /// The output's unblinded address on `network`.
    #[must_use]
    pub fn address(&self, network: &SimplicityNetwork) -> Address {
        Address::p2tr(
            secp256k1::SECP256K1,
            self.info.internal_key(),
            self.info.merkle_root(),
            None,
            network.address_params(),
        )
    }

    /// The leaf with this name.
    ///
    /// # Errors
    /// Returns `UnknownLeaf` when no leaf has the name.
    pub fn leaf(&self, name: &str) -> Result<&TreeLeaf, TreeError> {
        self.leaves
            .iter()
            .find(|leaf| leaf.name == name)
            .ok_or_else(|| TreeError::UnknownLeaf(name.to_string()))
    }

    /// The control block that reveals the named leaf.
    ///
    /// # Errors
    /// Returns `UnknownLeaf` when no leaf has the name.
    ///
    /// # Panics
    /// Never: every named leaf was added to the tree when it was fixed.
    pub fn control_block(&self, name: &str) -> Result<ControlBlock, TreeError> {
        let leaf = self.leaf(name)?;

        Ok(self
            .info
            .control_block(&(leaf.script.clone(), leaf.version))
            .expect("every leaf was added to the tree"))
    }

    /// The named Simplicity program, placed at its leaf: its address is this tree's output and its
    /// control block reveals its leaf. Spend it with a `ProgramInput` as any other program.
    ///
    /// # Errors
    /// Returns `UnknownLeaf` or `NotSimplicity`.
    pub fn program(&self, name: &str) -> Result<Program, TreeError> {
        self.leaf(name)?;

        let mut found = None;
        self.root.visit(0, &mut |node, _| {
            if let TapTree::Simplicity { name: n, program } = node
                && n == name
            {
                found = Some(program.clone());
            }
        });

        let program = found.ok_or_else(|| TreeError::NotSimplicity(name.to_string()))?;

        Ok(program.placed_in(Arc::clone(&self.info)))
    }

    /// A spend of the named tapscript leaf. `witness` lists the items the script consumes, the
    /// bottom of the stack first; the leaf script and its control block follow them.
    ///
    /// # Errors
    /// Returns `UnknownLeaf` or `NotTapscript`.
    pub fn tapscript_input(&self, name: &str, witness: Vec<TapscriptWitness>) -> Result<TapscriptInput, TreeError> {
        let leaf = self.leaf(name)?;

        if leaf.version != LeafVersion::default() {
            return Err(TreeError::NotTapscript(name.to_string()));
        }

        Ok(TapscriptInput {
            script: leaf.script.clone(),
            control_block: self.control_block(name)?,
            witness,
        })
    }

    /// The Merkle root, if the tree has any node.
    #[must_use]
    pub fn merkle_root(&self) -> Option<[u8; 32]> {
        self.info.merkle_root().map(Hash::to_byte_array)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use simplicityhl::Arguments;
    use simplicityhl::elements::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
    use simplicityhl::elements::script::Builder;

    use super::*;
    use crate::program::ArgumentsTrait;

    // The one-key program of the fixed-root layout: the key is a parameter in the data leaf.
    const ONE_KEY: &str = r"
        fn tapdata(pk: Pubkey) -> u256 {
            let ctx: Ctx8 = jet::tapdata_init();
            let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, pk);
            jet::sha_256_ctx_8_finalize(ctx)
        }

        fn main() {
            let pk: Pubkey = witness::PK;
            assert!(jet::eq_256(tapdata(pk), unwrap(jet::tappath(0))));
            jet::bip_0340_verify((pk, jet::sig_all_hash()), witness::SIG);
        }
    ";

    #[derive(Clone)]
    struct NoArguments;

    impl ArgumentsTrait for NoArguments {
        fn build_arguments(&self) -> Arguments {
            Arguments::default()
        }
    }

    fn one_key() -> Program {
        Program::new(ONE_KEY, &NoArguments).with_debug_symbols(false)
    }

    // The key whose secret is the scalar `n`.
    fn key(n: u8) -> XOnlyPublicKey {
        let mut scalar = [0u8; 32];
        scalar[31] = n;
        let secret = secp256k1::SecretKey::from_slice(&scalar).unwrap();
        secret.x_only_public_key(secp256k1::SECP256K1).0
    }

    fn exit_script(blocks: i64, pk: XOnlyPublicKey) -> Script {
        Builder::new()
            .push_int(blocks)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_slice(&pk.serialize())
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn key_or_exit(pk: XOnlyPublicKey) -> ContractTree {
        ContractTree::script_only(TapTree::branch(
            TapTree::branch(TapTree::simplicity("key", one_key()), TapTree::data(&pk.serialize())),
            TapTree::tapscript("exit", exit_script(144, pk)),
        ))
        .unwrap()
    }

    // The two-leaf tree reproduces the fixed-root layout's golden vector for secret key 1:
    // the same program, the key in the data leaf, the unspendable internal key.
    #[test]
    fn program_and_data_leaf_match_the_fixed_root_vector() {
        let tree = ContractTree::script_only(TapTree::branch(
            TapTree::simplicity("key", one_key()),
            TapTree::data(&key(1).serialize()),
        ))
        .unwrap();

        assert_eq!(
            hex::encode(one_key().get_cmr()),
            "c1a71ea2b1ccb88c315419a16ab142eab3864976863ee3c23ccb6bcaeee546fa"
        );
        assert_eq!(
            hex::encode(tree.script_pubkey().as_bytes()),
            "51208ac2af4e7e0c7c60b618b8c5d4639f130d4d76cd4e24d77855f084b54a052e7f"
        );
    }

    #[test]
    fn each_leaf_gets_a_control_block_that_opens_the_output() {
        let tree = key_or_exit(key(1));

        for leaf in tree.leaves() {
            let control = tree.control_block(&leaf.name).unwrap();

            assert_eq!(control.leaf_version, leaf.version);
            assert!(control.verify_taproot_commitment(
                secp256k1::SECP256K1,
                &tree.spend_info().output_key(),
                &leaf.script
            ));
        }

        // The program sits beside its data leaf and one level below the exit: its path is the data
        // leaf, then the exit leaf. The exit's path is the branch holding the other two.
        assert_eq!(tree.control_block("key").unwrap().merkle_branch.as_inner().len(), 2);
        assert_eq!(tree.control_block("exit").unwrap().merkle_branch.as_inner().len(), 1);
        assert_eq!(
            tree.control_block("key").unwrap().merkle_branch.as_inner()[0],
            tap_data_hash(&key(1).serialize())
        );
    }

    #[test]
    fn a_placed_program_pays_to_and_opens_its_tree() {
        let tree = key_or_exit(key(1));
        let program = tree.program("key").unwrap();
        let network = SimplicityNetwork::default_regtest();

        assert_eq!(program.get_script_pubkey(&network), tree.script_pubkey());
        assert_eq!(program.get_tr_address(&network), tree.address(&network));
        assert_eq!(program.get_cmr(), one_key().get_cmr());

        // The unplaced program pays elsewhere: its own one-leaf tree.
        assert_ne!(one_key().get_script_pubkey(&network), tree.script_pubkey());
    }

    #[test]
    fn a_tapscript_spend_carries_its_script_and_control_block() {
        let tree = key_or_exit(key(1));
        let input = tree.tapscript_input("exit", vec![TapscriptWitness::Signature]).unwrap();

        assert_eq!(input.script, exit_script(144, key(1)));
        assert_eq!(input.control_block, tree.control_block("exit").unwrap());
    }

    #[test]
    fn a_leaf_is_named_once_and_spent_by_its_kind() {
        let tree = key_or_exit(key(1));

        assert!(matches!(tree.program("exit"), Err(TreeError::NotSimplicity(_))));
        assert!(matches!(
            tree.tapscript_input("key", vec![]),
            Err(TreeError::NotTapscript(_))
        ));
        assert!(matches!(tree.program("nowhere"), Err(TreeError::UnknownLeaf(_))));

        let twice = ContractTree::script_only(TapTree::branch(
            TapTree::tapscript("exit", exit_script(1, key(1))),
            TapTree::tapscript("exit", exit_script(2, key(1))),
        ));
        assert!(matches!(twice, Err(TreeError::DuplicateName(_))));

        let same = ContractTree::script_only(TapTree::branch(
            TapTree::tapscript("a", exit_script(1, key(1))),
            TapTree::tapscript("b", exit_script(1, key(1))),
        ));
        assert!(matches!(same, Err(TreeError::DuplicateLeaf(_, _))));

        let stored = ContractTree::script_only(TapTree::simplicity("key", one_key().with_storage_capacity(1)));
        assert!(matches!(stored, Err(TreeError::ProgramHasStorage(_))));
    }

    // The tree reproduces the default single-program layout when it holds that program alone.
    #[test]
    fn one_leaf_matches_the_programs_own_output() {
        let tree = ContractTree::script_only(TapTree::simplicity("key", one_key())).unwrap();
        let network = SimplicityNetwork::default_regtest();

        assert_eq!(tree.script_pubkey(), one_key().get_script_pubkey(&network));
        assert_eq!(tree.leaves().len(), 1);
        assert!(XOnlyPublicKey::from_str(&tree.output_key().to_string()).is_ok());
    }
}
