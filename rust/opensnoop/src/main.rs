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
use libbpf::bpf_update_elem;
use libbpf::perf_reader_fd;
use libbpf::perf_reader_poll;
use libbpf::BpfProbeAttachType;
use libbpf::BpfProgType;
use std::ffi::CString;
use std::io;
use std::mem;
use std::os::raw::c_int;
use std::os::raw::c_void;

// Next steps:
// - Support command-line flags.
// - Make perf_reader_raw_callback a closure that captures relevant flags.
// - Refactor main() so it is not one enormous fn.
// - Add support for -f.
// - Add perf_reader_free() cleanup.
// - Implement getOnlineCpus() to determine this value.

fn main() -> io::Result<()> {
  // This value comes from the BPF_HASH() macro in bcc.
  let max_entries = 10240;
  let val_map = bpf_create_map::<u64, bindings::val_t>(libbpf::BpfMapType::Hash, max_entries)?;

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

  let mut readers: Vec<*mut libbpf::perf_reader> = Vec::with_capacity(cpus.len());

  // Open a perf buffer for each online CPU.
  // (This is what open_perf_buffer() in bcc/table.py does.)
  for (i, cpu) in cpus.iter().enumerate() {
    let reader = unsafe {
      bpf_open_perf_buffer(
        /* raw_cb */ Some(perf_reader_raw_callback),
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

    let mut perf_reader_fd = unsafe { perf_reader_fd(reader as *mut libbpf::perf_reader) };
    readers.push(reader as *mut libbpf::perf_reader);
    // https://stackoverflow.com/q/34691267/396304
    let perf_reader_fd_ptr = &mut perf_reader_fd as *mut _ as *mut std::ffi::c_void;
    let rc = unsafe {
      bpf_update_elem(
        perf_map.fd(),
        (cpus.as_ptr().offset(i as isize)) as *mut std::ffi::c_void,
        perf_reader_fd_ptr,
        libbpf::BPF_ANY,
      )
    };
    check_unix_error(rc)?;
  }

  println!(
    "{:6} {:16} {:4} {:3} {}",
    "PID", "COMM", "FD", "ERR", "PATH"
  );

  loop {
    let rc = unsafe { perf_reader_poll(cpus.len() as i32, readers.as_mut_ptr(), -1) };
    check_unix_error(rc)?;
  }

  // Ok(())
}

extern "C" fn perf_reader_raw_callback(
  _cb_cookie: *mut c_void,
  raw: *mut c_void,
  _raw_size: c_int,
) {
  let event = raw as *mut bindings::data_t;

  let ret = unsafe { (*event).ret };
  let (fd_s, err) = if ret >= 0 { (ret, 0) } else { (-1, -ret) };

  let (id, comm, fname) = unsafe { ((*event).id, (*event).comm, (*event).fname) };
  let pid = id >> 32;
  println!(
    "{:6} {:16} {:4} {:3} {}",
    pid,
    (unsafe { std::ffi::CStr::from_ptr(comm.as_ptr()) }).to_string_lossy(),
    fd_s,
    err,
    (unsafe { std::ffi::CStr::from_ptr(fname.as_ptr()) }).to_string_lossy(),
  );
}

fn check_unix_error(rc: c_int) -> io::Result<()> {
  if rc == -1 {
    Err(io::Error::last_os_error())
  } else {
    Ok(())
  }
}
