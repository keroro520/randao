use crate::DummyDataLoader;
use ckb_types::packed::OutPoint;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, ScriptHashType},
    packed::{Byte32, CellOutput, Script},
    prelude::*,
};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref ALWAYS_SUCCESS_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/always_success")[..]);
}

pub fn install(loader: &mut DummyDataLoader) {
    let data_capacity = Capacity::bytes(ALWAYS_SUCCESS_BIN.len()).unwrap();
    let cell_data = ALWAYS_SUCCESS_BIN.clone();
    let cell_output = CellOutput::new_builder()
        .lock(always_success())
        .build_exact_capacity(data_capacity)
        .unwrap();
    loader.add_cell(always_success_out_point(), cell_output, cell_data);
}

pub fn always_success_out_point() -> OutPoint {
    OutPoint::new(Byte32::zero(), 1234)
}

pub fn always_success() -> Script {
    let code_hash = CellOutput::calc_data_hash(&ALWAYS_SUCCESS_BIN.as_ref());
    Script::new_builder()
        .code_hash(code_hash)
        .hash_type(ScriptHashType::Data.into())
        .build()
}
