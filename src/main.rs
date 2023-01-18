// use byte_strings::{as_bytes, concat_bytes};
// use crypto::{self};
use libsecp256k1::{recover, sign, verify, Message, PublicKey, SecretKey, Signature};
use primitive_types::*;
use rlp::{encode, Encodable, RlpStream};
use sha3::{Digest, Keccak256};

// use basic::{GasLimit, GasPrice, Wei, H256, U256};
// use bytes::BytesMut;
// use nom::branch::alt;
// use nom::bytes::complete::tag;
// use nom::combinator::map;
// use nom::multi::many1;
// use nom::sequence::{pair, preceded};
use tezos_encoding::enc::BinWriter;
use tezos_encoding::encoding::HasEncoding;
use tezos_encoding::nom::NomReader;

pub mod address;
pub mod basic;

pub fn message(e: EthereumTransactionCommon) -> Message {
    let m = encode(&e);
    let m = m.as_ref();
    let t = Keccak256::digest(m);
    let tt = H256::from_slice(t.as_slice());

    let mes = Message::parse(tt.as_fixed_bytes());
    mes
}

fn string_to_sk_and_address(s: String) -> (SecretKey, H160) {
    let data: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
    let sk = SecretKey::parse(&data).unwrap();
    let pk = PublicKey::from_secret_key(&sk);
    let serialised = &pk.serialize()[1..];
    let kec = Keccak256::digest(serialised);
    (sk, H160::from_slice(&kec.as_slice()[12..]))
}

#[test]
fn test_sign_to_add() {
    let test_list = vec![
        (
            "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d",
            "90F8bf6A479f320ead074411a4B0e7944Ea8c9C1",
        ),
        (
            "DC38EE117CAE37750EB1ECC5CFD3DE8E85963B481B93E732C5D0CB66EE6B0C9D",
            "c5ed5d9b9c957be2baa01c16310aa4d1f8bc8e6f",
        ),
        (
            "80b28170e7c2cb2145c052d622ced9de477abcb287e0d23f07263cc30a260534",
            "D0a2dBb5e6F757fd2066a7664f413CAAC504BC95",
        ),
    ];
    test_list.iter().fold((), |_, (s, ea)| {
        let (_, a) = string_to_sk_and_address(s.to_string());
        let ea = H160::from_slice(&hex::decode(ea).unwrap());
        assert_eq!(a, ea);
    })
}

#[test]
fn testsign() {
    let (sk, _address) = string_to_sk_and_address(
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d".to_string(),
    );
    let pk = PublicKey::from_secret_key(&sk);
    let signed = sign_message(sk, 10, 3, 1000, 10000, [23; 20], 3);
    let mes = message(signed);
    let (s, ri) = sign(&mes, &sk);
    let v = verify(&mes, &s, &pk);
    let pk1 = recover(&mes, &s, &ri).unwrap();
    assert!(v);
    assert!(pk == pk1)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, HasEncoding, NomReader, BinWriter)]
pub struct EthereumTransactionCommon {
    /// A scalar value equal to the number of trans- actions sent by the sender
    pub nonce: basic::U256,
    /// EIP-2718 transaction type
    pub r#type: u8,
    /// A scalar value equal to the number of
    /// Wei to be paid per unit of gas for all computation
    /// costs incurred as a result of the execution of this
    /// transaction
    pub gas_price: basic::GasPrice,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later
    pub gas_limit: basic::GasLimit,
    /// The 160-bit address of the message call’s recipi-
    /// ent or, for a contract creation transaction
    pub to: address::EvmAddress,
    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account
    pub value: basic::Wei,
    /// Signature x-axis part of point on elliptic curve. See yellow paper, appendix F
    pub r: basic::H256,
    /// Signature, See yellow paper appendix F
    pub s: basic::H256,
    ///
    pub v: u8, //
}

fn sign_message(
    sk: SecretKey,
    nonce: usize,
    r#type: u8,
    gas_price: usize,
    gas_limit: usize,
    to: [u8; 20],
    value: usize,
) -> EthereumTransactionCommon {
    let mut stream = rlp::RlpStream::new_list(2);
    stream.append(&U256::from(nonce));
    stream.append(&r#type);
    stream.append(&U256::from(gas_price));
    stream.append(&U256::from(gas_limit));
    stream.append(&H160::from(to));
    stream.append(&U256::from(value));
    let t = Keccak256::digest(stream.as_raw());
    let tt = H256::from_slice(t.as_slice());

    let mes = Message::parse(tt.as_fixed_bytes());
    let (sig, ri) = sign(&mes, &sk);
    let (r, s) = match sig {
        Signature { r, s } => (
            basic::H256::from(H256::from(r.b32())),
            basic::H256::from(H256::from(s.b32())),
        ),
    };
    let v = ri.into();

    return EthereumTransactionCommon {
        nonce: basic::U256::from(U256::from(nonce)),
        r#type,
        gas_price: basic::GasPrice {
            value: basic::U256::from(U256::from(gas_price)),
        },
        gas_limit: basic::GasLimit {
            value: basic::U256::from(U256::from(gas_limit)),
        },
        to: address::EvmAddress::from(to),
        value: basic::Wei {
            value: basic::U256::from(U256::from(value)),
        },
        r,
        s,
        v,
    };
}

impl Encodable for EthereumTransactionCommon {
    fn rlp_append(&self, s: &mut RlpStream) {
        let nb: U256 = std::convert::Into::<U256>::into(self.nonce);
        s.append(&nb);
        s.append(&self.r#type);
        let gp: U256 = std::convert::Into::<U256>::into(self.gas_price.value);
        s.append(&gp);
        let gl: U256 = std::convert::Into::<U256>::into(self.gas_limit.value);
        s.append(&gl);
        let w: U256 = std::convert::Into::<U256>::into(self.value.value);
        s.append(&w);
        let add: H160 = std::convert::Into::<H160>::into(self.to);
        s.append(&add);
    }
}

fn main() {
    let a: u128 = 12;
    let a = H128::from(a.to_be_bytes());
    let b: [u8; 20] = [12; 20];
    let b = H160::from(b);
    let mut stream = rlp::RlpStream::new_list(2);
    stream.append(&a);
    stream.append(&b);
    stream.append(&b);

    print!("{:?}", stream.as_raw())
    // let c = sign1(10, 3, 1000, 10000, 458769, 3);
    // rlp_enc(c);
}
