extern crate libbpf;
extern crate libc;
extern crate structopt;

mod bindings;
mod generated_bytecode;

use generated_bytecode::generate_trace_entry;
use generated_bytecode::generate_trace_entry_pid;
use generated_bytecode::generate_trace_entry_tid;
use generated_bytecode::generate_trace_return;
use generated_bytecode::MAX_NUM_TRACE_ENTRY_INSTRUCTIONS;
use generated_bytecode::NUM_TRACE_ENTRY_INSTRUCTIONS;
use generated_bytecode::NUM_TRACE_ENTRY_PID_INSTRUCTIONS;
use generated_bytecode::NUM_TRACE_ENTRY_TID_INSTRUCTIONS;
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
use structopt::StructOpt;

// Next steps:
// - Refactor main() so it is not one enormous fn.
// - Add support for -f.
// - Add perf_reader_free() cleanup.
// - Implement getOnlineCpus() to determine this value.

const NANOS_PER_SECOND: f32 = 1_000_000_000.0;

#[derive(StructOpt)]
#[structopt(name = "opensnoop")]
#[repr(C)]
struct Options {
  #[structopt(
    long = "timestamp",
    short = "T",
    help = "include timestamp on output"
  )]
  timestamp: bool,

  #[structopt(
    long = "failed",
    short = "x",
    help = "only show failed opens"
  )]
  failed: bool,

  #[structopt(long = "pid", short = "p", help = "trace this PID only")]
  pid: Option<u32>,

  #[structopt(long = "tid", short = "t", help = "trace this TID only")]
  tid: Option<u64>,

  #[structopt(
    long = "duration",
    short = "d",
    help = "total duration of trace in seconds"
  )]
  duration: Option<u32>,

  #[structopt(
    long = "name",
    short = "n",
    help = "only print process names containing this name"
  )]
  name: Option<String>,
}

struct PerfReaderCallbackContext<'a> {
  options: &'a Options,
  initial_timestamp: u64,
}

fn main() -> io::Result<()> {
  let options = Options::from_args();

  // This value comes from the BPF_HASH() macro in bcc.
  let max_entries = 10240;
  let val_map = bpf_create_map::<u64, bindings::val_t>(libbpf::BpfMapType::Hash, max_entries)?;

  let cpus: [i32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
  let perf_map = bpf_create_map::<i32, u32>(libbpf::BpfMapType::PerfEventArray, cpus.len() as i32)?;

  let mut instructions: [bpf_insn; MAX_NUM_TRACE_ENTRY_INSTRUCTIONS] =
    unsafe { mem::uninitialized() };
  let num_instructions = if let Some(tid) = options.tid {
    generate_trace_entry_tid(&mut instructions, tid as i32, &val_map);
    NUM_TRACE_ENTRY_TID_INSTRUCTIONS
  } else if let Some(pid) = options.pid {
    generate_trace_entry_pid(&mut instructions, pid as i32, &val_map);
    NUM_TRACE_ENTRY_PID_INSTRUCTIONS
  } else {
    generate_trace_entry(&mut instructions, &val_map);
    NUM_TRACE_ENTRY_INSTRUCTIONS
  };
  let entry_prog = bpf_prog_load(
    BpfProgType::Kprobe,
    instructions.as_ptr(),
    num_instructions as i32,
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
  let mut readers: Vec<*mut libbpf::perf_reader> = Vec::with_capacity(cpus.len());
  let mut context = PerfReaderCallbackContext {
    options: &options,
    initial_timestamp: 0,
  };
  for (i, cpu) in cpus.iter().enumerate() {
    let reader = unsafe {
      bpf_open_perf_buffer(
        /* raw_cb */ Some(perf_reader_raw_callback),
        /* lost_cb */ None,
        /* cb_cookie */ &mut context as *mut _ as *mut std::ffi::c_void,
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

  if options.timestamp {
    print!("{:14}", "TIME(s)");
  }
  let pid_or_tid = if options.tid.is_some() { "PID" } else { "TID" };
  println!(
    "{:6} {:16} {:4} {:3} {}",
    pid_or_tid, "COMM", "FD", "ERR", "PATH"
  );

  let end_time = if let Some(duration) = options.duration {
    let mut time = libc::timespec {
      tv_sec: 0,
      tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut time) };
    check_unix_error(rc)?;

    time.tv_sec += duration as i64;
    Some(time)
  } else {
    None
  };

  loop {
    if let Some(end_time) = end_time {
      let mut current_time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
      };
      let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut current_time) };
      check_unix_error(rc)?;

      if current_time.tv_sec > end_time.tv_sec
        || (current_time.tv_sec == end_time.tv_sec && current_time.tv_nsec >= end_time.tv_nsec)
      {
        break;
      }
    }

    let rc = unsafe { perf_reader_poll(cpus.len() as i32, readers.as_mut_ptr(), -1) };
    check_unix_error(rc)?;
  }

  Ok(())
}

extern "C" fn perf_reader_raw_callback(cb_cookie: *mut c_void, raw: *mut c_void, _raw_size: c_int) {
  let context = unsafe { &mut *(cb_cookie as *mut PerfReaderCallbackContext) };
  let options = context.options;
  let event = unsafe { &*(raw as *mut bindings::data_t) };
  let ret = event.ret;

  if options.failed && ret >= 0 {
    return;
  }

  if let Some(ref name) = options.name {
    let comm = (unsafe { std::ffi::CStr::from_ptr(event.comm.as_ptr()) }).to_string_lossy();
    if !comm.contains(name.as_str()) {
      return;
    }
  }

  let (fd_s, err) = if ret >= 0 { (ret, 0) } else { (-1, -ret) };

  if options.timestamp {
    if context.initial_timestamp == 0 {
      context.initial_timestamp = event.ts;
    }

    let delta = event.ts - context.initial_timestamp;
    print!("{:<14.9}", delta as f32 / NANOS_PER_SECOND);
  }

  let id = if let Some(tid) = options.tid {
    tid
  } else {
    event.id >> 32
  };
  println!(
    "{:6} {:16} {:4} {:3} {}",
    id,
    (unsafe { std::ffi::CStr::from_ptr(event.comm.as_ptr()) }).to_string_lossy(),
    fd_s,
    err,
    (unsafe { std::ffi::CStr::from_ptr(event.fname.as_ptr()) }).to_string_lossy(),
  );
}

fn check_unix_error(rc: c_int) -> io::Result<()> {
  if rc == -1 {
    Err(io::Error::last_os_error())
  } else {
    Ok(())
  }
}
