// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::vec::IntoIter;

use corim_rs::{Corim, ProfileTypeChoice};

use coserv_rs::coserv::{Coserv, CoservProfile, ResultSetTypeChoice};
use cover::result::{Error, Result};
use cover::{CorimStore, EvRelation, EvsRelation, RvRelation};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct CoservParseResult<'a> {
    #[serde(rename = "rv-list")]
    pub rv_list: Vec<RvRelation<'a>>,
    #[serde(rename = "ev-list")]
    pub ev_list: Vec<EvRelation<'a>>,
    #[serde(rename = "evs-list")]
    pub evs_list: Vec<EvsRelation<'a>>,
}

impl<'a> CoservParseResult<'a> {
    pub fn new() -> Self {
        CoservParseResult {
            rv_list: vec![],
            ev_list: vec![],
            evs_list: vec![],
        }
    }

    pub fn extend(&mut self, other: CoservParseResult<'a>) {
        self.rv_list.extend(other.rv_list);
        self.ev_list.extend(other.ev_list);
        self.evs_list.extend(other.evs_list);
    }

    pub fn append(&mut self, other: &mut CoservParseResult<'a>) {
        self.rv_list.append(other.rv_list.as_mut());
        self.ev_list.append(other.ev_list.as_mut());
        self.evs_list.append(other.evs_list.as_mut());
    }

    pub fn update_from_coserv_result<'b>(
        &mut self,
        coserv_result: &ResultSetTypeChoice<'b>,
        profile: &Option<ProfileTypeChoice<'b>>,
    ) -> Result<()> {
        let mut updated = false;

        match coserv_result {
            ResultSetTypeChoice::ReferenceValues(rv) => {
                for rv_quad in rv.rv_quads.clone() {
                    let rvt = rv_quad.triple;
                    let authority = rv_quad.authorities;
                    self.rv_list.push(RvRelation::from_reference_triple_record(
                        &rvt, profile, &authority,
                    )?);
                    updated = true;
                }
            }
            ResultSetTypeChoice::TrustAnchors(ta) => {
                for ta_quad in ta.ak_quads.clone() {
                    let akt = ta_quad.triple;
                    let authority = ta_quad.authorities;
                    self.ev_list.push(EvRelation::from_attest_key_triple_record(
                        &akt, profile, &authority,
                    )?);
                    updated = true;
                }
            }
            _ => {}
        };

        match updated {
            true => Ok(()),
            false => Err(Error::custom("no relevant quads found in CoSERV result")),
        }
    }
}

impl Default for CoservParseResult<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CoservParseResult<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string_pretty(&self).unwrap();
        f.write_str(s.as_str())
    }
}

pub struct MemCoservStore<'a> {
    pub items: CoservParseResult<'a>,
}

impl MemCoservStore<'_> {
    pub fn new() -> Self {
        Self {
            items: CoservParseResult::new(),
        }
    }
}

impl<'a> CorimStore<'a> for MemCoservStore<'a> {
    type RvIter = IntoIter<RvRelation<'a>>;
    type EvIter = IntoIter<EvRelation<'a>>;
    type EvsIter = IntoIter<EvsRelation<'a>>;

    #[allow(clippy::needless_lifetimes)]
    fn add<'b>(&mut self, _corim: &Corim<'b>) -> Result<()> {
        Err(Error::custom(
            "CoRIMs not supported - this store holds CoSERV results instead",
        ))
    }

    fn iter_rv(&self) -> Self::RvIter {
        self.items.rv_list.clone().into_iter()
    }

    fn iter_ev(&self) -> Self::EvIter {
        self.items.ev_list.clone().into_iter()
    }

    fn iter_evs(&self) -> Self::EvsIter {
        self.items.evs_list.clone().into_iter()
    }
}

impl<'a> MemCoservStore<'a> {
    pub fn add_coserv_cbor_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let coserv = Coserv::from_cbor(bytes)
            .map_err(|_e| Error::custom("Failed to parse CoSERV from CBOR bytes."))?;
        let mut parsed = parse_coserv(&coserv)?;
        self.items.append(&mut parsed);
        Ok(())
    }
}

#[allow(clippy::needless_lifetimes)]
pub fn parse_coserv<'a, 'b>(coserv: &Coserv<'a>) -> Result<CoservParseResult<'b>> {
    if let Some(coserv_result_set) = &coserv.results {
        if let Some(result_set) = &coserv_result_set.result_set {
            let mut result = CoservParseResult::new();
            let profile = match &coserv.profile {
                CoservProfile::Oid(oid) => ProfileTypeChoice::Oid(oid.clone().into()),
                CoservProfile::Uri(uri) => ProfileTypeChoice::Uri(uri.clone().into()),
            };
            result.update_from_coserv_result(result_set, &Some(profile))?;
            Ok(result)
        } else {
            Err(Error::custom(
                "The CoSERV object has not been populated with results.",
            ))
        }
    } else {
        Err(Error::custom(
            "The CoSERV object has None in the result set.",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use cover::{CcaScheme, Scheme, Verifier};

    use crate::store::MemCoservStore;

    #[test]
    fn test_populate_store_from_coserv_data() {
        let mut store = MemCoservStore::new();

        let rv_coserv_bytes = include_bytes!("../test/coserv_rv_result.cbor");
        let ta_coserv_bytes = include_bytes!("../test/coserv_ta_result.cbor");

        store
            .add_coserv_cbor_bytes(rv_coserv_bytes)
            .expect("failed to add CCA reference value CoSERV results into the store");

        // The test data provides 13 reference values, but we shouldn't have any endorsed values yet
        assert_eq!(store.items.rv_list.len(), 13);
        assert_eq!(store.items.ev_list.len(), 0);
        assert_eq!(store.items.evs_list.len(), 0);

        store
            .add_coserv_cbor_bytes(ta_coserv_bytes)
            .expect("failed to add CCA trust anchor CoSERV results into the store");

        // The test data provides 1 endorsed values - so we should have that, plus the 13 reference values still
        assert_eq!(store.items.rv_list.len(), 13);
        assert_eq!(store.items.ev_list.len(), 1);
        assert_eq!(store.items.evs_list.len(), 0);
    }

    #[test]
    fn test_cover_verify() {
        let mut store = MemCoservStore::new();

        let evidence_bytes = include_bytes!("../test/ccatoken.cbor");
        let rv_coserv_bytes = include_bytes!("../test/coserv_rv_result.cbor");
        let ta_coserv_bytes = include_bytes!("../test/coserv_ta_result.cbor");

        store
            .add_coserv_cbor_bytes(rv_coserv_bytes)
            .expect("failed to add CCA reference value CoSERV results into the store");

        store
            .add_coserv_cbor_bytes(ta_coserv_bytes)
            .expect("failed to add CCA trust anchor CoSERV results into the store");

        let mut schemes = HashMap::new();
        let cca_scheme: Box<dyn Scheme> = Box::new(CcaScheme::new());
        schemes.insert("cca".to_string(), cca_scheme);

        let verifier = Verifier::new(store, schemes);

        let result = verifier
            .verify("cca", evidence_bytes, None)
            .expect("verifier did not create a result");

        let ear = result.ear;

        let submod_platform = ear
            .submods
            .get("platform")
            .expect("no platform submodule in EAR");

        let submod_realm = ear.submods.get("realm").expect("no realm submodule in EAR");

        // We should get full Affirming status for the platform, but Warning status for the realm (due to the absence of RIM/REM references)
        assert_eq!(submod_platform.status.to_string(), "affirming");
        assert_eq!(submod_realm.status.to_string(), "warning");
    }
}
