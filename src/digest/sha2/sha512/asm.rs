extern "C" {
    fn OCTAVO_sha512_compress(state: *mut u64, data: *const u8);
}

pub fn compress(state: &mut [u64], data: &[u8]) {
    assert_eq!(data.len(), 128);
    unsafe { OCTAVO_sha512_compress(state.as_mut_ptr(), data.as_ptr()) }
}
