use crate::crypto::hashing::{Hash, Hashable};
use crate::crypto::serialize::Serializable;
use bs58 as base58;
use libp2p::identity;
use std::time::SystemTime;

#[derive(PartialEq, Eq)]
pub struct PublicKey {
    key: identity::PublicKey,
}

pub type UserId = Hash<PublicKey>;

impl PublicKey {
    fn verify_bytes(&self, msg: &[u8], sig: &[u8]) -> bool {
        self.key.verify(msg, sig)
    }
}

impl Hashable for PublicKey {
    fn hash(&self) -> Hash<Self> {
        Hash::from_bytes(&self.key.clone().into_protobuf_encoding()).cast()
    }
}

impl Serializable for PublicKey {
    fn serialize(&self) -> String {
        base58::encode(self.key.clone().into_protobuf_encoding()).into_string()
    }

    fn deserialize(input: String) -> Option<Self> {
        match base58::decode(input).into_vec() {
            Ok(bytes) => match identity::PublicKey::from_protobuf_encoding(&bytes) {
                Ok(key) => Some(PublicKey { key }),
                _ => None,
            },
            _ => None,
        }
    }
}

pub struct PrivateKey {
    keypair: identity::Keypair,
}

impl PrivateKey {
    pub fn generate() -> Self {
        PrivateKey {
            keypair: identity::Keypair::generate_ed25519(),
        }
    }

    pub fn get_public(&self) -> PublicKey {
        PublicKey {
            key: self.keypair.public(),
        }
    }

    pub fn sign<T: Hashable>(&self, content: T) -> Contract<T> {
        let timestamp = SystemTime::now().elapsed().unwrap().as_millis();
        let mut bytes_to_sign = content.hash().get_bytes().to_vec();
        bytes_to_sign.extend(timestamp.to_be_bytes().iter());

        Contract {
            signee: self.get_public(),
            signature: self.sign_bytes(&bytes_to_sign),
            timestamp,
            content,
        }
    }

    fn sign_bytes(&self, msg: &[u8]) -> Vec<u8> {
        self.keypair.sign(msg).expect("Failed to sign bytes")
    }
}

pub struct Contract<T: Hashable> {
    pub signee: PublicKey,
    signature: Vec<u8>,
    pub timestamp: u128,
    pub content: T,
}

impl<T: Hashable> Contract<T> {
    pub fn verify(&self) -> bool {
        let mut bytes_to_sign = self.content.hash().get_bytes().to_vec();
        bytes_to_sign.extend(self.timestamp.to_be_bytes().iter());

        self.signee.verify_bytes(&bytes_to_sign, &self.signature)
    }
}

impl<T: Hashable> Hashable for Contract<T> {
    fn hash(&self) -> Hash<Contract<T>> {
        hash![self.signee, self.signature, self.timestamp, self.content]
    }
}

impl<T: Hashable + Serializable> Serializable for Contract<T> {
    fn serialize(&self) -> String {
        format!(
            "{} {} {} {}",
            self.signee.serialize(),
            self.signature.serialize(),
            self.timestamp.serialize(),
            self.content.serialize()
        )
    }

    fn deserialize(input: String) -> Option<Self> {
        let mut words = input.split_whitespace();
        let signee = PublicKey::deserialize(words.next()?.to_string())?;
        let signature = Vec::<u8>::deserialize(words.next()?.to_string())?;
        let timestamp = u128::deserialize(words.next()?.to_string())?;
        let rest = {
            let mut rest = String::new();
            let mut first = true;
            for word in words {
                if !first {
                    rest.push(' ');
                }
                rest.push_str(word);
                first = false;
            }
            rest
        };
        let content = T::deserialize(rest)?;

        Some(Contract {
            signee,
            signature,
            timestamp,
            content,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correct_contract() {
        let private = PrivateKey::generate();
        let message = 123;

        let contract = private.sign(message);

        assert!(contract.verify());
    }

    #[test]
    fn test_tampered_content() {
        let private = PrivateKey::generate();
        let message = 123;
        let mut contract = private.sign(message);

        contract.content = 321;

        assert!(!contract.verify());
    }

    #[test]
    fn test_tampered_signee() {
        let private = PrivateKey::generate();
        let message = 123;
        let mut contract = private.sign(message);

        contract.signee = PrivateKey::generate().get_public();

        assert!(!contract.verify());
    }
}
