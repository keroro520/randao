use crate::randao::Randao;
use ckb_types::{
    bytes::Bytes,
    core::{cell::CellMeta, BlockExt, EpochExt, HeaderView},
    packed::{Byte32, CellOutput, OutPoint},
};
use testkit::{Always, DummyDataLoader, Facility};

struct Campaign {
    deposit: u64,
    period: u64,
    id: OutPoint,
}

fn initialize() -> DummyDataLoader {
    let mut loader = DummyDataLoader::default();
    Always.install(&mut loader);
    Randao.install(&mut loader);
    loader
}

#[test]
fn test_start_campaign() {
    let loader = initialize();
}
