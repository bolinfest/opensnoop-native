extern crate libbpf;

mod bindings;

fn main() {
  // This value comes from the BPF_HASH() macro in bcc.
  let max_entries = 10240;
  let val_map =
    libbpf::bpf_create_map::<u64, bindings::val_t>(libbpf::BpfMapType::Hash, max_entries);

  // TODO: Implement getOnlineCpus() to determine this value.
  let num_cpu = 16;
  let perf_map = libbpf::bpf_create_map::<i32, u32>(libbpf::BpfMapType::PerfEventArray, num_cpu);

  println!("{:?} {:?}", val_map, perf_map);
}
