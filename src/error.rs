// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // -- validation --
    #[error("invalid value: {value:?}, expected {expected}")]
    InvalidValue {
        value: Box<dyn std::fmt::Debug + Send + Sync>,
        expected: &'static str,
    },

    // -- external --
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    #[error(transparent)]
    Time(#[from] std::time::SystemTimeError),

    #[error(transparent)]
    Ccatoken(#[from] ccatoken::token::Error),

    #[error(transparent)]
    Corim(#[from] corim_rs::Error),

    #[error(transparent)]
    Cover(#[from] cover::result::Error),

    #[error(transparent)]
    Ear(#[from] ear::Error),

    #[error(transparent)]
    Coserv(#[from] coserv_rs::error::CoservError),

    #[error(transparent)]
    Apiclient(#[from] veraison_apiclient::Error),

    // -- custom --
    #[error("{0}")]
    Custom(String),
}

impl Error {
    pub fn custom<T>(val: T) -> Self
    where
        T: Display,
    {
        Error::Custom(val.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
