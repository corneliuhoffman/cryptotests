// SPDX-FileCopyrightText: 2022 TriliTech <contact@trili.tech>
//
// SPDX-License-Identifier: MIT

//! Basic Ethereum types for computation
//!
//! Many of the functions in this module (all the `one` and `zero`) can be made
//! constant, but the underlying library and functions we use are not constant.
//! TODO: <https://gitlab.com/tezos/tezos/-/milestones/114>
use nom::bytes::complete::take;
use nom::combinator::map;
use primitive_types::{H256 as PTH256, U256 as PTU256};
use tezos_encoding::enc::{BinResult, BinWriter};
use tezos_encoding::encoding::{Encoding, HasEncoding};
use tezos_encoding::has_encoding;
use tezos_encoding::nom::{NomReader, NomResult};

/// Gas price newtype to wrap U256
#[derive(Debug, PartialEq, Eq, Clone, Copy, HasEncoding, NomReader, BinWriter)]
pub struct GasPrice {
    /// tezos_encoding doesn't support deriving reader and writer from newtypes so therefore this
    /// public field instead.
    pub value: U256,
}

impl GasPrice {
    /// Create a new gas price from serilizable u256
    pub fn new(value: U256) -> Self {
        Self { value }
    }

    /// Create a new gas price from primitive type
    pub fn from_u256(value: PTU256) -> Self {
        Self { value: U256(value) }
    }

    /// Zero
    pub fn zero() -> Self {
        Self {
            value: U256::zero(),
        }
    }

    /// One
    pub fn one() -> Self {
        Self { value: U256::one() }
    }
}

/// Gas limit newtype to wrap U256
#[derive(Debug, PartialEq, Eq, Clone, Copy, HasEncoding, NomReader, BinWriter)]
pub struct GasLimit {
    /// tezos_encoding doesn't support deriving reader and writer from newtypes so therefore this
    /// public field instead.
    pub value: U256,
}

impl GasLimit {
    /// Create a new gas limit from serilizable u256
    pub fn new(value: U256) -> Self {
        Self { value }
    }

    /// Create a new gas limit from primitive type
    pub fn from_u256(value: PTU256) -> Self {
        Self { value: U256(value) }
    }

    /// Zero
    pub fn zero() -> Self {
        Self {
            value: U256::zero(),
        }
    }

    /// One
    pub fn one() -> Self {
        Self { value: U256::one() }
    }
}

/// Amount or value in Wei. Newtype wrapper for U256
#[derive(Debug, PartialEq, Eq, Clone, Copy, HasEncoding, NomReader, BinWriter)]
pub struct Wei {
    /// tezos_encoding doesn't support deriving reader and writer from newtypes so therefore this
    /// public field instead.
    pub value: U256,
}

impl Wei {
    /// Create a new value in Wei from serlizable type
    pub fn new(value: U256) -> Self {
        Self { value }
    }

    /// Create a new value in Wei from primitive type
    pub fn from_u256(value: PTU256) -> Self {
        Self { value: U256(value) }
    }

    /// Zero
    pub fn zero() -> Self {
        Self {
            value: U256::zero(),
        }
    }

    /// One
    pub fn one() -> Self {
        Self { value: U256::one() }
    }
}

/// Unsigned 256 bit integers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct U256(PTU256);

has_encoding!(U256, U256_ENCODING, { Encoding::Custom });

impl U256 {
    /// Value one 0x00 31 times and then a 0x01
    pub fn one() -> U256 {
        U256(PTU256::one())
    }

    /// Value zero
    pub fn zero() -> U256 {
        U256(PTU256::zero())
    }

    /// Create from slice - data in big endian format
    pub fn from_slice_be(data: &[u8]) -> Self {
        U256(PTU256::from_big_endian(data))
    }
}

impl NomReader for U256 {
    fn nom_read(input: &[u8]) -> NomResult<Self> {
        map(take(core::mem::size_of::<PTU256>()), |x: &[u8]| {
            U256(x.try_into().expect("Expected 32 bytes for U256"))
        })(input)
    }
}

impl BinWriter for U256 {
    fn bin_write(&self, output: &mut Vec<u8>) -> BinResult {
        let mut temp = [0u8; core::mem::size_of::<PTU256>()];
        self.0.to_big_endian(temp.as_mut_slice());
        output.extend_from_slice(temp.as_slice());
        Ok(())
    }
}

impl From<PTU256> for U256 {
    fn from(v: PTU256) -> Self {
        Self(v)
    }
}

#[allow(clippy::from_over_into)]
impl Into<PTU256> for U256 {
    fn into(self) -> PTU256 {
        self.0
    }
}

/// 256 bit hash (Keccak)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct H256(PTH256);

has_encoding!(H256, H256_ENCODING, { Encoding::Custom });

impl H256 {
    /// Value zero
    pub fn zero() -> H256 {
        Self(PTH256::zero())
    }
}

impl From<&[u8]> for H256 {
    fn from(v: &[u8]) -> Self {
        H256(PTH256::from_slice(v))
    }
}

impl From<[u8; 32]> for H256 {
    fn from(v: [u8; 32]) -> Self {
        H256(PTH256::from(v))
    }
}

impl NomReader for H256 {
    fn nom_read(input: &[u8]) -> NomResult<Self> {
        map(take(core::mem::size_of::<PTH256>()), |x: &[u8]| {
            H256(PTH256::from_slice(x))
        })(input)
    }
}

impl BinWriter for H256 {
    fn bin_write(&self, output: &mut Vec<u8>) -> BinResult {
        output.extend_from_slice(self.0.as_bytes());
        Ok(())
    }
}

impl From<PTH256> for H256 {
    fn from(v: PTH256) -> Self {
        Self(v)
    }
}

#[allow(clippy::from_over_into)]
impl Into<PTH256> for H256 {
    fn into(self) -> PTH256 {
        self.0
    }
}
