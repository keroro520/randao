use crate::DummyDataLoader;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, ScriptHashType},
    packed::{CellOutput, OutPoint, Script, ScriptBuilder},
    prelude::*,
};

pub trait Facility {
    fn install(&self, loader: &mut DummyDataLoader) {
        let data = self.data().clone();
        let data_capacity = Capacity::bytes(data.len()).unwrap();
        let output = CellOutput::new_builder()
            .lock(Script::default())
            .build_exact_capacity(data_capacity)
            .unwrap();
        loader.add_cell(self.out_point(), output, data);
    }

    fn out_point(&self) -> OutPoint {
        let fake_tx_hash = CellOutput::calc_data_hash(self.data().as_ref());
        let fake_index = 0;
        OutPoint::new(fake_tx_hash, fake_index)
    }

    fn script_builder(&self) -> ScriptBuilder {
        let code_hash = CellOutput::calc_data_hash(self.data().as_ref());
        Script::new_builder()
            .code_hash(code_hash)
            .hash_type(ScriptHashType::Data.into())
    }

    fn script(&self) -> Script {
        self.script_builder().build()
    }

    fn data(&self) -> &Bytes;
}
