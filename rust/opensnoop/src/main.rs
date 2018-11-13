extern crate libbpf;

mod bindings;
mod generated_bytecode;

use generated_bytecode::generate_trace_entry;
use generated_bytecode::generate_trace_return;
use generated_bytecode::NUM_TRACE_ENTRY_INSTRUCTIONS;
use generated_bytecode::NUM_TRACE_RETURN_INSTRUCTIONS;
use libbpf::bpf_attach_kprobe;
use libbpf::bpf_create_map;
use libbpf::bpf_insn;
use libbpf::bpf_open_perf_buffer;
use libbpf::bpf_prog_load;
use libbpf::BpfProbeAttachType;
use libbpf::BpfProgType;
use std::ffi::CString;
use std::io;
use std::mem;
use std::os::raw::c_int;

fn main() -> io::Result<()> {
  // This value comes from the BPF_HASH() macro in bcc.
  let max_entries = 10240;
  let val_map = bpf_create_map::<u64, bindings::val_t>(libbpf::BpfMapType::Hash, max_entries)?;

  // TODO: Implement getOnlineCpus() to determine this value.
  let cpus: [i32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
  let perf_map = bpf_create_map::<i32, u32>(libbpf::BpfMapType::PerfEventArray, cpus.len() as i32)?;

  let mut instructions: [bpf_insn; NUM_TRACE_ENTRY_INSTRUCTIONS] = unsafe { mem::uninitialized() };
  generate_trace_entry(&mut instructions, &val_map);
  let entry_prog = bpf_prog_load(
    BpfProgType::Kprobe,
    instructions.as_ptr(),
    NUM_TRACE_ENTRY_INSTRUCTIONS as c_int,
  )?;
  let _kprobe = bpf_attach_kprobe(
    entry_prog,
    BpfProbeAttachType::Entry,
    CString::new("p_do_sys_open").unwrap().as_ptr(),
    CString::new("do_sys_open").unwrap().as_ptr(),
    None,
  )?;

  let mut ret_instructions: [bpf_insn; NUM_TRACE_RETURN_INSTRUCTIONS] =
    unsafe { mem::uninitialized() };
  generate_trace_return(&mut ret_instructions, &val_map, &perf_map);
  let return_prog = bpf_prog_load(
    BpfProgType::Kprobe,
    ret_instructions.as_ptr(),
    NUM_TRACE_RETURN_INSTRUCTIONS as c_int,
  )?;
  let _kretprobe = bpf_attach_kprobe(
    return_prog,
    BpfProbeAttachType::Return,
    CString::new("r_do_sys_open").unwrap().as_ptr(),
    CString::new("do_sys_open").unwrap().as_ptr(),
    None,
  )?;

  // Open a perf buffer for each online CPU.
  // (This is what open_perf_buffer() in bcc/table.py does.)
  for cpu in cpus.iter() {
    let reader = unsafe {
      // TODO: Implement raw_cb.
      bpf_open_perf_buffer(
        /* raw_cb */ None,
        /* lost_cb */ None,
        /* cb_cookie */ std::ptr::null_mut(),
        /* pid */ -1,
        *cpu,
        /* page_cnt */ 64,
      )
    };
    if reader.is_null() {
      panic!("Error calling bpf_open_perf_buffer()");
    }
  }

  Ok(())
}
