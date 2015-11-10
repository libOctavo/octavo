#[cfg(feature = "asm-sha256")]
mod asm;
#[cfg(feature = "asm-sha256")]
pub use self::asm::compress;

#[cfg(not(feature = "asm-sha256"))]
mod native;
#[cfg(not(feature = "asm-sha256"))]
pub use self::native::compress;
