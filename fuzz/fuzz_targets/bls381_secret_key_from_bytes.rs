#![no_main]
use libfuzzer_sys::fuzz_target;
use amcl::bls381::bls381::utils::{secret_key_to_bytes, secret_key_from_bytes};


fuzz_target!(|data: &[u8]| {
    if let Ok(big) = secret_key_from_bytes(data) {
        let round_trip = secret_key_to_bytes(&big);
        assert_eq!(data, round_trip);
    }
});
