#![no_main]
use libfuzzer_sys::fuzz_target;
use amcl::bls381::bls381::utils::{deserialize_g2, serialize_uncompressed_g2, serialize_g2};

fuzz_target!(|data: &[u8]| {
    if let Ok(point) = deserialize_g2(data) {
        let compressed = serialize_g2(&point).to_vec();
        let uncompressed = serialize_uncompressed_g2(&point).to_vec();

        let data = data.to_vec();
        assert!(compressed == data || uncompressed == data );
    }
});
