use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const EBPF_SRC_DIR: &str = "src/bpf";
const EBPF_SRC: &str = "procexec.bpf.c";

fn main() {
    ebpf_build_script();
    tonic_build_script();
}

fn tonic_build_script() {
    let proto_path = PathBuf::from("protos/procsearch.proto");
    tonic_build::compile_protos(&proto_path).unwrap();
    println!("cargo:rerun-if-changed={}", proto_path.display());
}

fn ebpf_build_script() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join("procexec.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(format!("{EBPF_SRC_DIR}/{EBPF_SRC}"))
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={EBPF_SRC_DIR}/{EBPF_SRC}");
    for direntry in std::fs::read_dir(EBPF_SRC_DIR).unwrap() {
        let direntry = direntry.unwrap();
        let path = direntry.path();
        if path.extension() == Some(OsStr::new("h")) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}
