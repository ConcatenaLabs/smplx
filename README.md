![](https://github.com/user-attachments/assets/c4661df7-6101-4c46-9376-dedaeef8056b)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/BlockstreamResearch/smplx/actions/workflows/crates.yml/badge.svg?branch=master)](https://github.com/BlockstreamResearch/smplx/workflows/crates.yml)
[![Integration](https://github.com/BlockstreamResearch/smplx/actions/workflows/fixtures.yml/badge.svg?branch=master)](https://github.com/BlockstreamResearch/smplx/workflows/fixtures.yml)
[![Community](https://img.shields.io/endpoint?color=neon&logo=telegram&label=Chat&url=https%3A%2F%2Ftg.sumanjay.workers.dev%2Fsimplicity_community)](https://t.me/simplicity_community)

# Smplx

> This is Sequentia's copy of Simplex, and it works with Sequentia networks only: it speaks Sequentia's transaction encoding, and refuses the Liquid and Elements networks at runtime with a message that says so. Use upstream Simplex for Liquid. [SEQUENTIA.md](SEQUENTIA.md) says what differs on Sequentia and how to use it there.

**A blazingly-fast, ux-first Simplicity development framework.**

## What

Simplex is a Rust-based, comprehensive development framework for [Simplicity](https://github.com/BlockstreamResearch/SimplicityHL) smart contracts, aiming to provide a rich tooling suite for implementing, testing, and deploying smart contracts. This copy deploys them on [Sequentia](https://github.com/ConcatenaLabs/Sequentia).

- CLI for managing simplicity-based projects.
- SDK with essential simplicity utilities.
- A local Sequentia chain for integration testing.
- Extensive framework configuration.

> [!WARNING]
> The framework is at the extremely early stage of development, unforeseen breaking changes and critical bugs are expected.

## Installation

```bash
curl -L https://smplx.simplicity-lang.org | bash
simplexup
```

See the [simplexup manual](simplexup/README.md) for more details.

## Getting started

Add `smplx-std` dependency to cargo:

```bash
cargo add --dev smplx-std
```

Optionally, initialize a new project:

```bash
simplex init <name>
```

## Usage

Simplex is a zero-config framework. However, it requires a `simplex.toml` file to exist in the project root. The default configuration is the following:

```toml
# Simplex config

[build]
src_dir = "./simf"
simf_files = ["*.simf"]
out_dir = "./src/artifacts"

[dependencies]
some_dep = { git = "<git url>", path = "<or relative path>", <tag | rev> = "<tag name | commit>" } 

[regtest]
chain = "sequentia"
mnemonic = "exist carry drive collect lend cereal occur much tiger just involve mean"
bitcoins = 10_000_000
rpc_port = 18443
rpc_user = "user"
rpc_password = "password"
node_bin = "<path to sequentiad; default: sequentiad on PATH>"

[test]
mnemonic = "exist carry drive collect lend cereal occur much tiger just involve mean"
bitcoins = 10_000_000
verbosity = 0 # 0 - none, 1 - debug, 2 - trace

[test.esplora]
url = "<esplora url>"
network = "SequentiaTestnet"

[test.rpc]
url = "<rpc url>"
username = "<rpc username>"
password = "<rpc password>"
```

Where:

- `build` (`simplex build` config)
  - `src_dir` - The simplicity contracts source directory.
  - `simf_files` - A glob pattern indicating which contracts are in scope.
  - `out_dir` - The output directory where contracts artifacts are generated.
- `dependencies` (`simplex install` config)
  - The list of SimplicityHL dependencies to install.
- `regtest` (`simplex regtest` config)
  - `chain` - `sequentia`, the default and the only chain this copy starts: a Bitcoin regtest parent and a Sequentia node anchored to it.
  - `mnemonic` - The signer's mnemonic regtest will send initial funds to.
  - `bitcoins` - Initial coins available to the signer.
  - `rpc_port` - The port the Sequentia node's RPC will listen on.
  - `rpc_user` - The Sequentia node's RPC username.
  - `rpc_password` - The Sequentia node's RPC password.
  - `node_bin` - The node binary. Without it, `sequentiad` is looked up on `PATH`.
- `test` (`simplex test` config)
  - `mnemonic` - The signer's mnemonic internal regtest will send initial funds to.
  - `bitcoins` - Initial coins available to the signer.
  - `verbosity` - Simplicity pruning log level.
  - The regtest `simplex test` starts uses the binaries named in `[regtest]`.
  - `esplora`
    - `url` - Esplora API endpoint url.
    - `network` - Esplora network type: `SequentiaTestnet`. Not used when `rpc` is given, since the network is then read from the node.
  - `rpc`
    - `url` - A Sequentia node's RPC endpoint url. The network is read from the node, and a node that is not Sequentia's is refused.
    - `username` - The node's RPC username.
    - `password` - The node's RPC password.

### CLI

Simplex CLI provides the following commands:

- `simplex init` - Initializes a new Simplex project.
- `simplex config` - Prints the current config.
- `simplex install <dep>` - Installs SimplicityHL dependencies. Without a `<dep>` provided, installs everything listed in the `[dependencies]` config section. With one or more `<dep>` arguments, appends new entries to the config and then installs everything. The bare name `std` pins the latest `SimplicityHL` [standard library](https://github.com/BlockstreamResearch/simplicityhl-std) release.
- `simplex build` - Generates simplicity artifacts.
- `simplex regtest` - Starts a local Sequentia chain: a Bitcoin regtest parent and a Sequentia node anchored to it.
- `simplex test` - Runs Simplex tests. It runs them with `smplx-nextest`, which `simplexup` installs; without it, a stock `cargo-nextest` on `PATH` serves, and `SIMPLEX_NEXTEST` names any other.
- `simplex clean` - Cleans up generated artifacts.

To view the available options, run the help command:

```bash
simplex -h
```

### Example

Check out the complete project examples in the `examples` directory to learn more.

## Contributing

We are open to any mind-blowing ideas! Please take a look at our [contributing guidelines](CONTRIBUTING.md) to get involved.

## Future work

- [x] SimplicityHL storage compatibility.
- [x] SimplicityHL dependencies management.
- [ ] SDK support for confidential assets, taproot signer, and custom witness signatures.
- [ ] SimplicityHL contracts fuzz testing.
- [ ] SimplicityHL contracts static analyzer.
- [ ] Local regtest 10x speedup.
- [ ] Regtest cheat codes.
- [ ] Browser compatibility.
- [ ] Comprehensive documentation.

Check out the full roadmap [here](https://github.com/orgs/BlockstreamResearch/projects/3).

## License

The framework is released under the MIT License.
