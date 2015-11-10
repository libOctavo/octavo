use gcc;

fn path_for(file: &str) -> String {
    format!("asm/x86/{}.S", file)
}

fn compile(file: &str) {
    gcc::Config::new()
        .file(path_for(file))
        .compile(&format!("lib{}.a", file));
    println!(r#"cargo:rustc-cfg=feature="asm-{}""#, file)
}

pub fn build() {
    println!("Building with x86 asm support");
    // compile("cpuid");
    compile("md5");
    compile("sha1");
    compile("sha256");
    compile("sha512");
}
