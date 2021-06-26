use bs58 as base58;
use std::convert::TryInto;

pub trait Serializable
where
    Self: Sized,
{
    fn serialize(&self) -> String;
    fn deserialize(input: String) -> Option<Self>;
}

impl Serializable for u64 {
    fn serialize(&self) -> String {
        base58::encode(self.to_be_bytes()).into_string()
    }

    fn deserialize(input: String) -> Option<Self> {
        let bytes = base58::decode(input)
            .into_vec()
            .map(|bytes| bytes.as_slice().try_into());
        if let Ok(Ok(bytes)) = bytes {
            Some(u64::from_be_bytes(bytes))
        } else {
            None
        }
    }
}

impl Serializable for u128 {
    fn serialize(&self) -> String {
        base58::encode(self.to_be_bytes()).into_string()
    }

    fn deserialize(input: String) -> Option<Self> {
        let bytes = base58::decode(input)
            .into_vec()
            .map(|bytes| bytes.as_slice().try_into());
        if let Ok(Ok(bytes)) = bytes {
            Some(u128::from_be_bytes(bytes))
        } else {
            None
        }
    }
}

impl Serializable for Vec<u8> {
    fn serialize(&self) -> String {
        base58::encode(self).into_string()
    }

    fn deserialize(input: String) -> Option<Self> {
        match base58::decode(input).into_vec() {
            Ok(bytes) => Some(bytes),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::contracts::{Contract, PrivateKey, UserId};
    use crate::crypto::hashing::{Hash, Hashable};
    use crate::transactions::license::*;
    use crate::transactions::Transaction;

    fn compare_deserialization<T: Serializable + Eq>(original: T) {
        let string = original.serialize();
        let deserialized = T::deserialize(string);
        assert!(deserialized == Some(original));
    }

    fn dummy_unsigned_creation() -> UnsignedLicenseCreation {
        UnsignedLicenseCreation { seed: 123 }
    }

    fn dummy_unsigned_transfer() -> UnsignedLicenseTransfer {
        let license: LicenseId = hash![123];
        let recipient: UserId = hash![321];
        UnsignedLicenseTransfer { license, recipient }
    }

    #[test]
    fn serialize_u64() {
        let original: u64 = 123;
        compare_deserialization(original);
    }

    #[test]
    fn serialize_u128() {
        let original: u128 = 123;
        compare_deserialization(original);
    }

    #[test]
    fn serialize_hash() {
        let number: u128 = 123;
        let original: Hash<u128> = hash![number];
        compare_deserialization(original);
    }

    #[test]
    fn serialize_contract() {
        let private = PrivateKey::generate();
        let contract: Contract<u64> = private.sign(123);
        compare_deserialization(contract);
    }

    #[test]
    fn serialize_unsigned_creation() {
        let creation = dummy_unsigned_creation();
        compare_deserialization(creation);
    }

    #[test]
    fn serialize_unsigned_transfer() {
        let transfer = dummy_unsigned_transfer();
        compare_deserialization(transfer);
    }

    #[test]
    fn serialize_creation() {
        let private = PrivateKey::generate();
        let unsigned_creation = dummy_unsigned_creation();
        let creation: LicenseCreation = private.sign(unsigned_creation);
        compare_deserialization(creation);
    }

    #[test]
    fn serialize_transfer() {
        let private = PrivateKey::generate();
        let unsigned_transfer = dummy_unsigned_transfer();
        let transfer: LicenseTransfer = private.sign(unsigned_transfer);
        compare_deserialization(transfer);
    }

    #[test]
    fn serialize_transaction() {
        let private = PrivateKey::generate();
        let unsigned_creation = dummy_unsigned_creation();
        let unsigned_transfer = dummy_unsigned_transfer();

        let creation = Transaction::LicenseCreation(private.sign(unsigned_creation));
        let transfer = Transaction::LicenseTransfer(private.sign(unsigned_transfer));

        compare_deserialization(creation);
        compare_deserialization(transfer);
    }
}
