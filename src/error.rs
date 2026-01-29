// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use coserv_rs::error::CoservError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CoservError(#[from] CoservError),

    #[error(transparent)]
    CorimError(#[from] corim_rs::Error),
}

pub type Result<A> = std::result::Result<A, Error>;
