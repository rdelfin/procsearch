use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC_DIR: &str = "src/bpf";
const SRC: &str = "procexec.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join("procexec.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(format!("{SRC_DIR}/{SRC}"))
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    for direntry in std::fs::read_dir("src/bpf").unwrap() {
        let direntry = direntry.unwrap();
        let path = direntry.path();
        if path.extension() == Some(OsStr::new("h")) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}
