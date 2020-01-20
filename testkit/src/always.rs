use ckb_types::{
    bytes::Bytes,
};
use lazy_static::lazy_static;
use crate::Facility;

lazy_static! {
    pub static ref ALWAYS_SUCCESS_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/always_success")[..]);
}

pub struct Always;

impl Facility for Always {
    fn data(&self) -> &Bytes {
        &ALWAYS_SUCCESS_BIN
    }
}
