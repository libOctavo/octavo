extern {
    fn OCTAVO_sha256_compress(state: *mut u32, data: *const u8);
}

pub fn compress(state: &mut [u32], data: &[u8]) {
    assert_eq!(data.len(), 64);
    unsafe { OCTAVO_sha256_compress(state.as_mut_ptr(), data.as_ptr()) }
}
