extern crate gcc;

mod asm;

use std::env;

fn main() {
    if let None = env::var_os("CARGO_FEATURE_NO_ASM") {
        asm::build();
    }
}
