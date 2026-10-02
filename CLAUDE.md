# Working on smplx (Sequentia's copy)

Notes for AI coding agents and new contributors. [README.md](README.md) is
upstream's description of Simplex; [SEQUENTIA.md](SEQUENTIA.md) says what this
copy adds for Sequentia and how to use it. Node and consensus conventions live in
the [`Sequentia`](https://github.com/ConcatenaLabs/Sequentia) repository.

## How this repository relates to upstream

- `master` carries upstream's history unaltered (BlockstreamResearch/smplx, from
  the release tag it is based on) with Sequentia's commits on top, merged through
  pull requests with merge commits so each commit stays whole. Keep that set
  small and rebaseable: to move to a new upstream release, replay the commits
  after the old tag onto the new one, rerun everything below, and land the result
  through a pull request.
- Keep generic commits (useful to upstream: a fee-asset setting, the RPC-only
  provider, configurable binaries) apart from Sequentia-specific ones (the patched
  `elements`, the networks, the regtest chain, this file). Never mix the two in
  one commit, so the generic ones can be offered upstream as they are.
- Do not open pull requests, issues or comments upstream from here.
- Change the SWK commit of the `elements` patch in every place it appears
  (`Cargo.toml`, `examples/basic/Cargo.toml`, `SEQUENTIA.md`) together.

## Things that are expensive to get wrong

- **No fee fallback.** On a Sequentia network the signer pays in the asset it is
  given or the one asset a transaction moves. Never default it to the policy
  asset: on Sequentia that asset (the Sequence token) is one fee asset among
  equals, and a mainnet node accepts none until its operator lists them. For
  the same reason no asset is sent by default: `Signer::send` is refused on a
  Sequentia network, and a send names its asset with `send_asset`.
- **Explicit by default.** Change on Sequentia is explicit unless a confidential
  input forces a blinded output. Never make confidentiality the default.
- **Simplicity active from genesis.** A test chain needs
  `-evbparams=simplicity:-1:::`; the form `simplicity:0:::` activates only at
  height 384, and until then a Simplicity output is spendable by anyone.
- **Signatures have fixed lengths.** The signer grinds every ECDSA signature
  to 71 bytes with its sighash byte, so a spend's weight is known before it is
  signed and its fee is right the first time. Plain low-R signing is 70 or 71
  bytes, and a fee set on the draft can then fall one weight unit short.
- **Padding is fixed before signing.** A full signature hash commits to every
  input's annex, so every annex is in place before any signature that counts.
  An input not yet signed holds `[placeholder, annex]`: the node reads an annex
  only from a stack of two or more items (BIP 341), and the signing environment
  is built to read it the same way (`program::bip341_annexes`).
- **Sequentia only.** The build speaks Sequentia's transaction encoding, so every
  entry point refuses a Liquid or Elements network, and a node is identified by
  asking it (`getfeeexchangerates`), never from a configuration key.
- **Contract keys are not wallet keys.** Programs and tapscript leaves are signed
  under `m/8383h/{coin}h/0h`, the wallet's own inputs under `m/84h/{coin}h/0h`.
- **Change is valued, not counted.** It is kept at or above the node's dust
  threshold in the fee asset's atoms and joins the fee only below it.
- **The compiler is pinned upstream.** `simplicityhl` is the version upstream
  pins, the same one `sequentia-contracts` pins. A different version moves
  commitment roots, and with them addresses. The `Parity` workflow fails when
  the compiler or either Simplicity library differs from that pin, or when the
  libraries differ from the node's.

## Before every pull request

```sh
cargo fmt --all --check
RUSTFLAGS=-Dwarnings cargo clippy --workspace --all-targets --all-features
cargo test --workspace --all-features
scripts/sequentia-example.sh /path/to/sequentiad
```

The last line needs a built `sequentiad` and `cargo-nextest`; it starts and stops
its own nodes and leaves nothing running.

<!-- BEGIN SHARED AGENT CONVENTIONS: identical in every Sequentia repo. Change it in all of them together. -->
## Working with git and GitHub here

These rules are the same in every Sequentia repository. They are repeated in each
one because this file is the only thing an agent is guaranteed to read, whatever
machine it is working from.

**Nothing pushed to GitHub credits Claude, Anthropic, or any AI tool.** No
`Co-Authored-By: Claude` trailer, no `Claude-Session:` trailer or `claude.ai`
link, no "Generated with Claude Code" in a commit message or a pull request body,
no `claude/*` branch names or session ids, and no mention in source, comments,
docs or issue text. Agent tooling offers several of these by default; compose the
message without them rather than stripping them afterwards.

**Author every commit as the person the session is working for.** Several people
commit in these repositories and an agent always runs on behalf of one of them,
so derive the author from the authenticated GitHub account rather than from a
list of names that goes stale the moment somebody new arrives:

    git -c user.name="$(gh api user --jq '.name // .login')" \
        -c user.email="$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')" \
        commit ...

That address is the GitHub `noreply` form, which is what links a commit to its
account and keeps private addresses out of a public history. When `gh` is not
authenticated as the person the work belongs to, ask them instead of guessing.

**Never infer the author from `git log`.** The clones carry no `user.name` or
`user.email`, so `git commit` stops with "Author identity unknown" and the
nearest answer to hand is the author of the last commit — which is whoever
pushed last and says nothing about who is working now. Attributing a commit to
someone who did not write it puts their name on code they never reviewed, and
taking it back costs a history rewrite and a force-push over commits other
machines have already pulled.

**Every change lands through a pull request that you merge yourself, at once.**
There is no reviewer on this project; the pull request exists so the reasoning is
recorded beside the diff. Branch, push, open it, merge it, delete the branch, all
in one sitting. Pushing straight to the default branch is the rule most often
broken here, and it is the one that costs the record. A pull request stays open
only when the repository owner asks for that specific one, and that never carries
over to the next.

**Name branches `area/short-description`**: `fix/`, `doc/`, `feature/`, `test/`,
`build/`, or the component being changed. Never a tool name, a session id, or
`worktree-*`.

**Write the subject as `area: what changed`**, one line, 72 characters at the
outside and 50 where you can manage it. Put the reasoning in the body, and
explain why rather than what.

**These repositories are public and world-readable.** Never commit private keys,
seeds, `wallet.dat`, RPC credentials, `.env` files or API tokens. Read the diff
before every commit. Secrets belong on the server and in offline backups.

**A file belongs to the repository whose code it describes.** Decide which repo
owns it before writing it; if it landed in the wrong one, move it rather than
deleting it.

**Documentation is part of the change, not a follow-up.** A change that makes a
README, a doc page, a runbook or a code comment wrong is not finished until that
text is right again, in the same pull request as the code. Before you open the
pull request, search the repository for whatever you renamed, moved or removed —
the old binary name, the old path, the old flag, the old command — and fix every
hit. If the change falsifies another repository's documentation, that repository
gets its own pull request in the same sitting. A stale instruction costs a new
user more than a missing one: they trust it, run it, it fails, and the failure
reads as broken software rather than as an out-of-date sentence.

**Write documentation to be timeless.** Assume the reader is new, arrived today,
and wants to know what the software is and how to use it right now. They do not
care what changed, what it used to be called, or which version added what. So
write in the present tense about current behaviour, and leave the history out:
no changelogs, no "new in", no "recently", no "coming soon", no status or
progress sections, no roadmaps, no dated notes. Quote a version number only where
the reader cannot act without it, and prefer pointing at the file that carries it
over copying the digits. Timeless does not mean thin — what the product is, who
it is for, and how to install, configure and use it all still belong there, in
full. Documentation written this way survives a release without an edit, which is
what keeps it true; the history already has homes in the git log, the tags and
the release notes.

**Push the same day you commit.** The testnet server pulls only from GitHub, so a
branch left on one laptop is invisible to every other machine and to the box.
<!-- END SHARED AGENT CONVENTIONS -->
