extern crate gcc;

#[cfg(target_arch = "x86_64")]
mod asm {
    use gcc;

    fn path_for(file: &str) -> String {
        format!("asm/x86_64/{}.S", file)
    }

    fn compile(file: &str) {
        gcc::Config::new()
            .file(path_for(file))
            .compile(&format!("lib{}.a", file));
        println!(r#"cargo:rustc-cfg=feature="asm-{}""#, file)
    }

    pub fn build() {
        println!("Building with x86-64 asm support");
        compile("cpuid");
        compile("md5");
        compile("sha1");
        compile("sha256");
        compile("sha512");
    }
}

#[cfg(all(not(target_arch = "x86_64")))]
mod asm {
    pub fn build(_: &str) {
    }
}

use std::env;

fn main() {
    if let None = env::var_os("CARGO_FEATURE_NO_ASM") {
        asm::build();
    }
}
