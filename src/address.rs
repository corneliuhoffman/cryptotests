// SPDX-FileCopyrightText: 2022 TriliTech <contact@trili.tech>
//
// SPDX-License-Identifier: MIT

//! Representation of Ethereum addresses
//!
//! We need to support Ethereum addresses for compatibility, so that
//! we can read Ethereum transactions, etc.
//!
//! Additionally, some addresses have special meaning - for example
//! locations of precompiled contracts or contract creation.
use nom::bytes::complete::take;
use nom::combinator::map;
use primitive_types::H160;
use tezos_encoding::enc::{BinResult, BinWriter};
use tezos_encoding::encoding::{Encoding, HasEncoding};
use tezos_encoding::has_encoding;
use tezos_encoding::nom::{NomReader, NomResult};

/// An address of an EVM contract
///
/// This should be compatible with the Ethereum addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct EvmAddress(H160);

impl EvmAddress {
    /// Get an address from unsigned 64-bit integer, big endian.
    pub fn from_u64_be(v: u64) -> Self {
        EvmAddress(H160::from_low_u64_be(v))
    }
}

has_encoding!(EvmAddress, EVMADDRESS_ENCODING, { Encoding::Custom });

#[allow(clippy::from_over_into)]
impl Into<H160> for EvmAddress {
    fn into(self) -> H160 {
        self.0
    }
}

impl From<[u8; 20]> for EvmAddress {
    fn from(v: [u8; 20]) -> Self {
        Self(v.into())
    }
}

impl NomReader for EvmAddress {
    fn nom_read(input: &[u8]) -> NomResult<Self> {
        map(take(core::mem::size_of::<H160>()), |x| {
            EvmAddress(H160::from_slice(x))
        })(input)
    }
}

impl BinWriter for EvmAddress {
    fn bin_write(&self, output: &mut Vec<u8>) -> BinResult {
        output.extend_from_slice(self.0.as_bytes());
        Ok(())
    }
}

/// The address for contract used for creating contracts
///
/// Ethereum has a set of precompiled/special contracts. Creating
/// contracts is implemented as one such contract.
#[allow(dead_code)]
const CREATE_CONTRACT: EvmAddress = EvmAddress(H160::zero());
