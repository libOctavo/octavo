extern "C" {
    fn OCTAVO_sha1_compress(state: *mut u32, data: *const u8);
}

pub fn compress(state: &mut [u32], data: &[u8]) {
    unsafe { OCTAVO_sha1_compress(state.as_mut_ptr(), data.as_ptr()) }
}
