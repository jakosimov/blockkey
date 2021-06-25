use crate::crypto::contracts::{Contract, UserId};
use crate::crypto::hashing::*;

pub struct UnsignedLicenseCreation {
    pub seed: u64,
}

impl Serializable for UnsignedLicenseCreation {
    fn serialize(&self) -> String {
        format!("CRT {}", self.seed.serialize())
    }

    fn deserialize(input: String) -> Option<Self> {
        let mut words = input.split_whitespace();

        match (words.next(), words.next()) {
            (Some("CRT"), Some(seed)) => {
                u64::deserialize(seed.to_string()).map(|seed| UnsignedLicenseCreation { seed })
            }
            _ => None,
        }
    }
}

pub struct UnsignedLicenseTransfer {
    pub license: LicenseId,
    pub recipient: UserId,
}

impl Serializable for UnsignedLicenseTransfer {
    fn serialize(&self) -> String {
        format!(
            "TSF {} {}",
            self.license.serialize(),
            self.recipient.serialize()
        )
    }

    fn deserialize(input: String) -> Option<Self> {
        let mut words = input.split_whitespace();

        match (words.next(), words.next(), words.next()) {
            (Some("TSF"), Some(license_id), Some(recipient)) => {
                match (
                    LicenseId::deserialize(license_id.to_string()),
                    UserId::deserialize(recipient.to_string()),
                ) {
                    (Some(license), Some(recipient)) => {
                        Some(UnsignedLicenseTransfer { license, recipient })
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

pub type LicenseCreation = Contract<UnsignedLicenseCreation>;
pub type LicenseTransfer = Contract<UnsignedLicenseTransfer>;
pub type LicenseId = Hash<LicenseCreation>;

impl Hashable for UnsignedLicenseCreation {
    fn hash(&self) -> Hash<Self> {
        hash![self.seed]
    }
}

impl Hashable for UnsignedLicenseTransfer {
    fn hash(&self) -> Hash<Self> {
        hash![self.license, self.recipient]
    }
}
