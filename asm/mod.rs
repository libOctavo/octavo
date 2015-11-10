macro_rules! build {
    ($arch:expr => $path:ident) => {
        #[cfg(target_arch = $arch)]
        mod $path;
        #[cfg(target_arch = $arch)]
        pub use self::$path::build;
    }
}

build!("x86_64" => x86_64);
build!("x86" => x86);

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
fn build() {
}
