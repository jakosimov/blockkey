use crate::crypto::serialize::Serializable;
use crate::transactions::license::{LicenseCreation, LicenseTransfer};

pub mod license;
pub mod state;

#[derive(PartialEq, Eq)]
pub enum Transaction {
    LicenseCreation(LicenseCreation),
    LicenseTransfer(LicenseTransfer),
}

impl Serializable for Transaction {
    fn serialize(&self) -> String {
        match self {
            Transaction::LicenseCreation(creation) => creation.serialize(),
            Transaction::LicenseTransfer(transfer) => transfer.serialize(),
        }
    }

    fn deserialize(input: String) -> Option<Self> {
        if let Some(creation) = LicenseCreation::deserialize(input.clone()) {
            Some(Transaction::LicenseCreation(creation))
        } else {
            LicenseTransfer::deserialize(input).map(Transaction::LicenseTransfer)
        }
    }
}