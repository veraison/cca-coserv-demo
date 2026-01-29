// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

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

use crate::error::Result;

/// Creates and returns a CoSERV query to obtain the reference values that would be needed to appraise the given CCA evidence
pub fn reference_value_query_from_evidence<'a>(evidence: &Evidence) -> Result<Coserv<'a>> {
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

#[cfg(test)]
mod tests {
    use ccatoken::token::Evidence;

    use crate::query::{reference_value_query_from_evidence, trust_anchor_query_from_evidence};

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
}
