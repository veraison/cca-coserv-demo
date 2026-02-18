# CCA CoSERV Demo

This project demonstrates how to use the [CoRIM Verifier (cover)](https://github.com/veraison/cover) to verify and appraise an Arm CCA attestation token, using [CoSERV](https://datatracker.ietf.org/doc/draft-ietf-rats-coserv/) as the source of trust anchors and reference values.


## How to Build
This is a Rust project so you need to [install Rust](https://rust-lang.org/tools/install/) first.

Then simply build as follows:

```
cargo build
```


## Installation and Usage

Install by running this command from the repo root:

```bash
cargo install --path . --locked
```

Example usage:

```bash
ccacoserv-cli --evidence test/ccatoken.cbor --coserv-server https://veraison.test.linaro.org:11443 --pretty
```

To see a list of available commands, run:

```bash
ccacoserv-cli --help
```
