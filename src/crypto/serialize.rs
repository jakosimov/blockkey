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
