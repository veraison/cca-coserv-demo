// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use log::debug;

use ccatoken::token::Evidence;

use corim_rs::{
    ClassIdTypeChoice, ClassMapBuilder, ExtensionValue, InstanceIdTypeChoice, TaggedUeidType,
    UeidType,
};

use coserv_rs::{
    coserv::{
        ArtifactTypeChoice, Coserv, CoservBuilder, CoservProfile, CoservQueryBuilder,
        EnvironmentSelectorMap, OpensslVerifier, ResultTypeChoice, StatefulClass,
        StatefulClassBuilder, StatefulInstance, StatefulInstanceBuilder,
    },
    discovery::ResultVerificationKey,
};

use veraison_apiclient::{
    Discovery, DiscoveryBuilder, coserv::QueryRunner, coserv::QueryRunnerBuilder,
};

use crate::error::{Error, Result};

/// Creates and returns a CoSERV query to obtain the reference values that would be needed to appraise the given CCA evidence
pub fn reference_value_query_from_evidence<'a>(evidence: &Evidence) -> Result<Coserv<'a>> {
    // NOTE: corim_rs::TaggedBytes could be a better choice here, but since the
    // latest impl-id tag (560) is not supported yet in the veraison EDS, we will
    // stick with 600 for now.
    let v = ExtensionValue::Tag(
        600,
        Box::new(ExtensionValue::Bytes(
            evidence.platform_claims.impl_id.as_slice().into(),
        )),
    );
    let id = ClassIdTypeChoice::Extension(v);
    let cca_fvp_class_map = ClassMapBuilder::new().class_id(id).build()?;

    let classes: Vec<StatefulClass> = vec![
        StatefulClassBuilder::new()
            .environment(cca_fvp_class_map)
            .build()?,
    ];

    let rv_query = CoservQueryBuilder::new()
        .artifact_type(ArtifactTypeChoice::ReferenceValues)
        .result_type(ResultTypeChoice::CollectedArtifacts)
        .environment_selector(EnvironmentSelectorMap::Class(classes))
        .build()?;

    let rv_coserv = CoservBuilder::new()
        .profile(CoservProfile::Uri(
            "tag:arm.com,2023:cca_platform#1.0.0".into(),
        ))
        .query(rv_query)
        .build()?;

    Ok(rv_coserv)
}

/// Creates and returns a CoSERV query to obtain the trust anchor(s) that would be needed to verify the given CCA evidence
pub fn trust_anchor_query_from_evidence<'a>(evidence: &Evidence) -> Result<Coserv<'a>> {
    let ueid = UeidType::new(evidence.platform_claims.inst_id.as_slice().into());
    let cca_fvp_instance_id = InstanceIdTypeChoice::Ueid(TaggedUeidType::new(ueid));
    let instances: Vec<StatefulInstance> = vec![
        StatefulInstanceBuilder::new()
            .environment(cca_fvp_instance_id)
            .build()?,
    ];

    // create query map
    let ta_query = CoservQueryBuilder::new()
        .artifact_type(ArtifactTypeChoice::TrustAnchors)
        .result_type(ResultTypeChoice::CollectedArtifacts)
        .environment_selector(EnvironmentSelectorMap::Instance(instances))
        .build()?;

    // create coserv map
    let ta_coserv = CoservBuilder::new()
        .profile(CoservProfile::Uri(
            "tag:arm.com,2023:cca_platform#1.0.0".into(),
        ))
        .query(ta_query)
        .build()?;

    Ok(ta_coserv)
}

/// Convenient wrapper around the [QueryRunner] that also includes a signature verifier and any
/// other client-side state that might be needed.
pub struct QueryClient {
    query_runner: QueryRunner,
    verifier: Option<OpensslVerifier>,
}

impl<'a> QueryClient {
    pub async fn run_discovery(
        coserv_service_base_url: &str,
        ca_cert: Option<&PathBuf>,
    ) -> Result<QueryClient> {
        let discoverer = ca_cert
            .map_or(DiscoveryBuilder::new(), |c| {
                DiscoveryBuilder::new().with_root_certificate(c.clone())
            })
            .with_base_url(coserv_service_base_url.to_string())
            .build()?;

        let discovery_doc = Discovery::get_coserv_discovery_document_json(&discoverer).await?;

        debug!(
            "discovered api endpoints: {:?}",
            discovery_doc.api_endpoints
        );

        // Extract the request-response API endpoint
        let endpoint = discovery_doc
            .api_endpoints
            .get("CoSERVRequestResponse")
            .ok_or_else(|| {
                Error::custom("missing key CoSERVRequestResponse in discovery document")
            })?;

        let coserv_request_response_url = format!("{coserv_service_base_url}{endpoint}");

        let query_runner = ca_cert
            .map_or(QueryRunnerBuilder::new(), |c| {
                QueryRunnerBuilder::new().with_root_certificate(c.clone())
            })
            .with_request_response_url(coserv_request_response_url)
            .build()?;

        // Extract the verification key and make an OpenSslVerifier from it
        let verification_key = discovery_doc.result_verification_key;
        let verifier: Option<OpensslVerifier> = match verification_key {
            ResultVerificationKey::Jose(jwk) => {
                if jwk.is_empty() {
                    // It is not valid for the server to supply an empty key array
                    // (Servers that do not support signed results should omit the key array field altogether)
                    return Err(Error::custom(
                        "the CoSERV server has returned an empty set of verification keys",
                    ));
                } else if jwk.len() > 1 {
                    // It is valid for the server to return multiple keys.
                    // However, we can't support this due to https://github.com/veraison/coserv-rs/issues/10
                    // We want to catch this as a visible error case.
                    return Err(Error::custom(
                        "the CoSERV server has returned multiple verification keys, which is valid but not supported",
                    ));
                } else {
                    let jwk_str = &jwk[0].to_string();
                    debug!("The JWK string for the verification key is {}", jwk_str);
                    let verifier = OpensslVerifier::from_jwk(jwk_str)
                        .map_err(|e| Error::Custom(e.to_string()))?;
                    Some(verifier)
                }
            }
            ResultVerificationKey::Cose(_) => {
                // We requested the discovery document as JSON, not CBOR, so this case should not be possible
                return Err(Error::custom(
                    "verification key should be a JWK in a JSON discovery document",
                ));
            }
            ResultVerificationKey::Undefined => {
                // This is valid, and means that the server does not support verification
                debug!("The CoSERV server does not support signed results.");
                None
            }
        };

        let client = QueryClient {
            query_runner,
            verifier,
        };

        Ok(client)
    }

    pub async fn run_query(&self, query: &Coserv<'a>, request_signed: bool) -> Result<Coserv<'a>> {
        let result = if request_signed {
            if let Some(verifier) = &self.verifier {
                self.query_runner
                    .execute_query_signed_extracted(query, verifier)
                    .await?
            } else {
                return Err(Error::custom(
                    "signed CoSERV result was requested, but not supported by the server",
                ));
            }
        } else {
            self.query_runner.execute_query_unsigned(query).await?
        };
        Ok(result)
    }

    pub fn supports_signing(&self) -> bool {
        self.verifier.is_some()
    }
}

#[cfg(test)]
mod tests {
    use ccatoken::token::Evidence;

    use crate::query::*;

    #[test]
    fn test_reference_value_query() {
        let evidence_bytes = include_bytes!("../test/ccatoken.cbor");
        let evidence = Evidence::decode(evidence_bytes.as_slice())
            .expect("failed to decode the CCA test evidence");
        let query = reference_value_query_from_evidence(&evidence)
            .expect("failed to build the CCA reference value query");
        let _b64 = query
            .to_b64_url()
            .expect("failed to convert the CCA reference value query to b64-url string");
        // TODO(paulhowardarm): In theory, these queries should resolve to stable and predictable b64-URL strings.
        //                      This doesn't work at the moment, because the data model is ill-advisedly including a timestamp - an error of judgement in the CoSERV spec
        //                      See: https://github.com/ietf-rats-wg/draft-ietf-rats-coserv/issues/56
        // assert_eq!(b64, "ogB4I3RhZzphcm0uY29tLDIwMjM6Y2NhX3BsYXRmb3JtIzEuMC4wAaQAAgGhAIGBoQDZAlhYIH9FTEYCAQEAAAAAAAAAAAADAD4AAQAAAFBYAAAAAAAAAsB0MjAyNi0wMS0yOFQxNjoxMjo0OVoDAA");
    }

    #[test]
    fn test_trust_anchor_query() {
        let evidence_bytes = include_bytes!("../test/ccatoken.cbor");
        let evidence = Evidence::decode(evidence_bytes.as_slice())
            .expect("failed to decode the CCA test evidence");
        let query = trust_anchor_query_from_evidence(&evidence)
            .expect("failed to build the CCA trust anchor query");
        let _b64 = query
            .to_b64_url()
            .expect("failed to convert the CCA trust anchor query to b64-url string");
        // TODO(paulhowardarm): See comment above
        // assert_eq!(b64, "ogB4I3RhZzphcm0uY29tLDIwMjM6Y2NhX3BsYXRmb3JtIzEuMC4wAaQAAgGhAIGBoQDZAlhYIH9FTEYCAQEAAAAAAAAAAAADAD4AAQAAAFBYAAAAAAAAAsB0MjAyNi0wMS0yOFQxNjoxMjo0OVoDAA");
    }

    #[tokio::test]
    async fn test_run_discovery() {
        let base_url = "https://veraison.test.linaro.org:11443";
        let ca_cert = None;
        let _client = QueryClient::run_discovery(base_url, ca_cert.as_ref())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_run_query_unsigned_ok() {
        let base_url = "https://veraison.test.linaro.org:11443";
        let ca_cert = None;
        let client = QueryClient::run_discovery(base_url, ca_cert.as_ref())
            .await
            .unwrap();
        let evidence_bytes = include_bytes!("../test/ccatoken.cbor");
        let evidence = Evidence::decode(evidence_bytes.as_slice())
            .expect("failed to decode CCA test evidence");
        let query = trust_anchor_query_from_evidence(&evidence)
            .expect("failed to build the CCA trust anchor query");

        let result = client.run_query(&query, false).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_query_signed_ok() {
        let base_url = "https://veraison.test.linaro.org:11443";
        let ca_cert = None;
        let client = QueryClient::run_discovery(base_url, ca_cert.as_ref())
            .await
            .unwrap();
        let evidence_bytes = include_bytes!("../test/ccatoken.cbor");
        let evidence = Evidence::decode(evidence_bytes.as_slice())
            .expect("failed to decode CCA test evidence");
        let query = trust_anchor_query_from_evidence(&evidence)
            .expect("failed to build the CCA trust anchor query");

        let result = client.run_query(&query, true).await;

        assert!(result.is_ok());
    }
}
