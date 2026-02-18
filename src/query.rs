// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use log::debug;

use ccatoken::token::Evidence;

use corim_rs::{
    ClassIdTypeChoice, ClassMapBuilder, ExtensionValue, InstanceIdTypeChoice, TaggedUeidType,
    UeidType,
};

use coserv_rs::coserv::{
    ArtifactTypeChoice, Coserv, CoservBuilder, CoservProfile, CoservQueryBuilder,
    EnvironmentSelectorMap, ResultTypeChoice, StatefulClass, StatefulClassBuilder,
    StatefulInstance, StatefulInstanceBuilder,
};

use veraison_apiclient::{Discovery, DiscoveryBuilder, coserv::QueryRunnerBuilder};

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

pub async fn run_query<'a>(
    coserv_service_base_url: &str,
    ca_cert: Option<&PathBuf>,
    coserv_query: &Coserv<'a>,
    request_signed: bool,
) -> Result<Coserv<'a>> {
    // cannot support signed coserv response yet
    if request_signed {
        return Err(Error::InvalidValue {
            value: Box::new(request_signed),
            expected: "request_signed = false",
        });
    }

    let coserv_request_response_url = run_discovery(coserv_service_base_url, ca_cert).await?;

    let query_runner = ca_cert
        .map_or(QueryRunnerBuilder::new(), |c| {
            QueryRunnerBuilder::new().with_root_certificate(c.clone())
        })
        .with_request_response_url(coserv_request_response_url.to_string())
        .build()?;

    let coserv_result = query_runner.execute_query_unsigned(coserv_query).await?;

    Ok(coserv_result)
}

pub async fn run_discovery(
    coserv_service_base_url: &str,
    ca_cert: Option<&PathBuf>,
) -> Result<String> {
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

    let endpoint = discovery_doc
        .api_endpoints
        .get("CoSERVRequestResponse")
        .ok_or_else(|| Error::custom("missing key CoSERVRequestResponse in discovery document"))?;

    let coserv_request_response_url = format!("{coserv_service_base_url}{endpoint}");

    Ok(coserv_request_response_url)
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
        let result = run_discovery(base_url, ca_cert.as_ref()).await.unwrap();

        assert_eq!(
            result,
            format!("{base_url}/endorsement-distribution/v1/coserv/{{query}}")
        );
    }

    #[tokio::test]
    async fn test_run_query_ok() {
        let base_url = "https://veraison.test.linaro.org:11443";
        let ca_cert = None;
        let evidence_bytes = include_bytes!("../test/ccatoken.cbor");
        let evidence = Evidence::decode(evidence_bytes.as_slice())
            .expect("failed to decode CCA test evidence");
        let query = trust_anchor_query_from_evidence(&evidence)
            .expect("failed to build the CCA trust anchor query");

        let result = run_query(base_url, ca_cert.as_ref(), &query, false).await;

        assert!(result.is_ok());
    }
}
