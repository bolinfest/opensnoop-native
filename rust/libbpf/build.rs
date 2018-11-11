extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
  // Note this line is not for debugging:
  // the build will not work without it!
  println!("cargo:rustc-link-lib=bpf");

  // The bindgen::Builder is the main entry point
  // to bindgen, and lets you build up options for
  // the resulting bindings.
  let bindings = bindgen::Builder::default()
    // The input header we would like to generate
    // bindings for.
    .header("wrapper.h")
    .rustfmt_bindings(true)
    .whitelist_type("bpf_map_type")
    .whitelist_type("bpf_probe_attach_type")
    .whitelist_type("bpf_prog_type")
    .whitelist_function("bpf_attach_kprobe")
    .whitelist_function("bpf_create_map")
    .whitelist_function("bpf_prog_load")
    .whitelist_var("bpf_map_type_.*")
    .whitelist_var("LINUX_VERSION_CODE_CONST")
    .whitelist_var("LOG_BUF_SIZE_CONST")
    // Finish the builder and generate the bindings.
    .generate()
    // Unwrap the Result and panic on failure.
    .expect("Unable to generate bindings");

  // Write the bindings to the $OUT_DIR/bindings.rs file.
  let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
  bindings
    .write_to_file(out_path.join("bindings.rs"))
    .expect("Couldn't write bindings!");
}
