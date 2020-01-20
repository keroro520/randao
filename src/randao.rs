use ckb_types::bytes::Bytes;
use lazy_static::lazy_static;
use testkit::Facility;

lazy_static! {
    pub static ref RANDAO_BIN: Bytes = Bytes::from(&include_bytes!("../specs/cells/randao")[..]);
}

pub struct Randao;

impl Facility for Randao {
    fn data(&self) -> &Bytes {
        &RANDAO_BIN
    }
}
