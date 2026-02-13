use std::{
    collections::HashMap,
    fs::{self, File},
    io::prelude::*,
    path::PathBuf,
};

use log::{debug, info};

use cover::{CcaScheme, Scheme, Verifier};

use ccatoken::token::Evidence;

use crate::{
    Cli,
    error::{Error, Result},
    query::{reference_value_query_from_evidence, run_query, trust_anchor_query_from_evidence},
    store::MemCoservStore,
};

pub async fn verify(args: &Cli) -> Result<()> {
    let mut schemes = HashMap::new();
    let cca_scheme: Box<dyn Scheme> = Box::new(CcaScheme::new());
    schemes.insert("cca".to_string(), cca_scheme);

    debug!(
        "supported schemes: {}",
        schemes
            .keys()
            .map(|k| k.as_ref())
            .collect::<Vec<&str>>()
            .join(", ")
    );

    let ca_cert_path = args.ca_cert.as_ref().map(PathBuf::from);

    let raw_evidence = fs::read(&args.evidence)?;
    let evidence = Evidence::decode(raw_evidence.as_slice())?;

    let ta_query = trust_anchor_query_from_evidence(&evidence)?;
    let rv_query = reference_value_query_from_evidence(&evidence)?;

    let ta_result = run_query(
        &args.coserv_server,
        ca_cert_path.as_ref(),
        &ta_query,
        false, // request unsigned coserv response
    )
    .await?;

    let rv_result = run_query(
        &args.coserv_server,
        ca_cert_path.as_ref(),
        &rv_query,
        false, // request unsigned coserv response
    )
    .await?;

    debug!("\nreceived coserv results: {rv_result:?}, {ta_result:?}",);

    // populate the coserv store with the coserv results
    //
    let mut coserv_store = MemCoservStore::new();
    coserv_store.add_coserv_cbor_bytes(rv_result.to_cbor()?.as_slice())?;
    coserv_store.add_coserv_cbor_bytes(ta_result.to_cbor()?.as_slice())?;

    // use cover to perform verification using the coserv store
    //
    let verifier = Verifier::new(coserv_store, schemes);
    let attestation_result = verifier.verify("cca", raw_evidence.as_slice(), None)?;

    // write EAR to output file
    //
    let ear_json = match args.pretty {
        true => serde_json::to_string_pretty(&attestation_result.ear)?,
        false => serde_json::to_string(&attestation_result.ear)?,
    };

    let out_path = match &args.output {
        Some(path) => path.clone(),
        None => {
            let mut path = PathBuf::from(&args.evidence)
                .file_stem()
                .map(|x| x.to_string_lossy())
                .ok_or(Error::custom("could not create output path"))?
                .to_string();
            path.push_str(".ear.json");
            path
        }
    };

    info!("ear: {ear_json}");

    info!("writing result to {out_path}");

    let mut out = match args.force {
        true => File::create(&out_path),
        false => File::create_new(&out_path),
    }
    .map_err(|e| Error::custom(format!("could not open {out_path:?} for writing: {e}",)))?;

    out.write_all(ear_json.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap_verbosity_flag::Verbosity;

    use crate::{Cli, verify::verify};

    #[tokio::test]
    async fn verify_ok() {
        let mock_cli = Cli {
            coserv_server: String::from("https://veraison.test.linaro.org:11443"),
            evidence: String::from("test/ccatoken.cbor"),
            pretty: false,
            output: None,
            ca_cert: None,
            force: true,
            verbosity: Verbosity::default(),
        };

        let result = verify(&mock_cli).await;

        assert!(result.is_ok(), "verify failed: {:?}", result);
    }

    #[tokio::test]
    async fn wrong_coserv_server() {
        let mock_cli = Cli {
            coserv_server: String::from("https://veraison.test.linaro.org:8443"),
            evidence: String::from("test/ccatoken.cbor"),
            pretty: false,
            output: None,
            ca_cert: None,
            force: true,
            verbosity: Verbosity::default(),
        };

        let result = verify(&mock_cli).await;

        assert!(
            result.is_err(),
            "verify should fail for wrong coserv server: {:?}",
            result
        );
    }
}
