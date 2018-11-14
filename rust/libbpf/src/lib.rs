mod raw_libbpf;

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::mem;
use std::mem::size_of;
use std::option::Option;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;

pub use raw_libbpf::bpf_insn;
pub use raw_libbpf::bpf_open_perf_buffer;
pub use raw_libbpf::bpf_update_elem;
pub use raw_libbpf::perf_reader;
pub use raw_libbpf::perf_reader_fd;
pub use raw_libbpf::perf_reader_poll;
pub const BPF_ANY: u64 = raw_libbpf::BPF_ANY_CONST as u64;

pub enum BpfMapType {
  Unspec,
  Hash,
  Array,
  ProgArray,
  PerfEventArray,
  PerCpuHash,
  PerCpuArray,
  StackTrace,
  CgroupArray,
  LruHash,
  LruPerCpuHash,
  LpmTrie,
  ArrayOfMaps,
  HashOfMaps,
  DevMap,
  SockMap,
  CpuMap,
  XskMap,
  SockHash,
  CgroupStorage,
  ReusePortSockArray,
}

fn to_map_type(bpf_map_type: BpfMapType) -> raw_libbpf::bpf_map_type {
  #![allow(non_snake_case)]
  match bpf_map_type {
    BpfMapType::Unspec => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_UNSPEC,
    BpfMapType::Hash => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_HASH,
    BpfMapType::Array => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_ARRAY,
    BpfMapType::ProgArray => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_PROG_ARRAY,
    BpfMapType::PerfEventArray => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BpfMapType::PerCpuHash => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_PERCPU_HASH,
    BpfMapType::PerCpuArray => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY,
    BpfMapType::StackTrace => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_STACK_TRACE,
    BpfMapType::CgroupArray => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_CGROUP_ARRAY,
    BpfMapType::LruHash => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_LRU_HASH,
    BpfMapType::LruPerCpuHash => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_LRU_PERCPU_HASH,
    BpfMapType::LpmTrie => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_LPM_TRIE,
    BpfMapType::ArrayOfMaps => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_ARRAY_OF_MAPS,
    BpfMapType::HashOfMaps => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_HASH_OF_MAPS,
    BpfMapType::DevMap => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_DEVMAP,
    BpfMapType::SockMap => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_SOCKMAP,
    BpfMapType::CpuMap => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_CPUMAP,
    BpfMapType::XskMap => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_XSKMAP,
    BpfMapType::SockHash => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_SOCKHASH,
    BpfMapType::CgroupStorage => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_CGROUP_STORAGE,
    BpfMapType::ReusePortSockArray => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
  }
}

#[derive(Debug)]
pub struct BpfMap {
  /// Wrap the fd as a File so that it is automatically closed when it goes out
  /// of scope.
  fd: File,
}

impl BpfMap {
  pub fn fd(&self) -> i32 {
    self.fd.as_raw_fd()
  }
}

pub fn bpf_create_map<K, V>(bpf_map_type: BpfMapType, max_entries: c_int) -> io::Result<BpfMap> {
  let key_size = size_of::<K>() as i32;
  let value_size = size_of::<V>() as i32;
  // TODO: Create a typesafe enum for map flags and make it a param.
  let map_flags: c_int = 0;
  let name = CString::new("not currently configurable").unwrap();
  let map_fd = unsafe {
    raw_libbpf::bpf_create_map(
      to_map_type(bpf_map_type),
      name.as_ptr(),
      key_size,
      value_size,
      max_entries,
      map_flags,
    )
  };

  fd_to_file(map_fd, "bpf_create_map").map(|fd| BpfMap { fd })
}

pub enum BpfProgType {
  Unspec,
  SocketFilter,
  Kprobe,
  SchedCls,
  SchedAct,
  Tracepoint,
  Xdp,
  PerfEvent,
  CgroupSkb,
  CgroupSock,
  LwtIn,
  LwtOut,
  LwtXmit,
  SockOps,
  SkSkb,
  CgroupDevice,
  SkMsg,
  RawTracepoint,
  CgroupSockAddr,
  LwtSeg6Local,
  LircMode2,
  SkReuseport,
}

fn to_prog_type(bpf_prog_type: BpfProgType) -> raw_libbpf::bpf_prog_type {
  #![allow(non_snake_case)]
  match bpf_prog_type {
    BpfProgType::Unspec => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_UNSPEC,
    BpfProgType::SocketFilter => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER,
    BpfProgType::Kprobe => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_KPROBE,
    BpfProgType::SchedCls => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_SCHED_CLS,
    BpfProgType::SchedAct => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_SCHED_ACT,
    BpfProgType::Tracepoint => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT,
    BpfProgType::Xdp => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_XDP,
    BpfProgType::PerfEvent => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_PERF_EVENT,
    BpfProgType::CgroupSkb => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_CGROUP_SKB,
    BpfProgType::CgroupSock => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_CGROUP_SOCK,
    BpfProgType::LwtIn => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_LWT_IN,
    BpfProgType::LwtOut => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_LWT_OUT,
    BpfProgType::LwtXmit => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_LWT_XMIT,
    BpfProgType::SockOps => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_SOCK_OPS,
    BpfProgType::SkSkb => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_SK_SKB,
    BpfProgType::CgroupDevice => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_CGROUP_DEVICE,
    BpfProgType::SkMsg => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_SK_MSG,
    BpfProgType::RawTracepoint => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_RAW_TRACEPOINT,
    BpfProgType::CgroupSockAddr => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    BpfProgType::LwtSeg6Local => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_LWT_SEG6LOCAL,
    BpfProgType::LircMode2 => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_LIRC_MODE2,
    BpfProgType::SkReuseport => raw_libbpf::bpf_prog_type_BPF_PROG_TYPE_SK_REUSEPORT,
  }
}

#[derive(Debug)]
pub struct BpfProg {
  /// Wrap the fd as a File so that it is automatically closed when it goes out
  /// of scope.
  fd: File,
}

pub fn bpf_prog_load(
  bpf_prog_type: BpfProgType,
  insns: *const raw_libbpf::bpf_insn,
  insn_len: c_int,
) -> io::Result<BpfProg> {
  let name = CString::new("not currently configurable").unwrap();
  let license = CString::new("GPL").unwrap();
  let mut log_buf =
    unsafe { mem::uninitialized::<[c_char; raw_libbpf::LOG_BUF_SIZE_CONST as usize]>() };

  // Make sure the first character is \0 so strlen(log_buf) is 0 if nothing is written.
  log_buf[0] = 0;

  let prog_fd = unsafe {
    let log_buf_size = log_buf.len() as u32;
    raw_libbpf::bpf_prog_load(
      to_prog_type(bpf_prog_type),
      name.as_ptr(),
      insns,
      insn_len * (size_of::<raw_libbpf::bpf_insn>() as i32),
      license.as_ptr(),
      raw_libbpf::LINUX_VERSION_CODE_CONST as u32,
      /* log_level */ 1,
      log_buf.as_mut_ptr(),
      log_buf_size,
    )
  };

  match fd_to_file(prog_fd, "bpf_prog_load") {
    Ok(fd) => Ok(BpfProg { fd }),
    Err(e) => {
      let log_msg = unsafe { std::ffi::CStr::from_ptr(log_buf.as_ptr()) };
      Err(io::Error::new(e.kind(), log_msg.to_string_lossy()))
    }
  }
}

pub enum BpfProbeAttachType {
  Entry,
  Return,
}

#[derive(Debug)]
pub struct Kprobe {
  /// Wrap the fd as a File so that it is automatically closed when it goes out
  /// of scope.
  fd: File,
}

pub fn bpf_attach_kprobe(
  prog: BpfProg,
  attach_type: BpfProbeAttachType,
  ev_name: *const c_char,
  fn_name: *const c_char,
  fn_offset: Option<u64>,
) -> io::Result<Kprobe> {
  let kprobe_fd = unsafe {
    raw_libbpf::bpf_attach_kprobe(
      prog.fd.as_raw_fd(),
      to_probe_attach_type(attach_type),
      ev_name,
      fn_name,
      fn_offset.unwrap_or(0),
    )
  };

  fd_to_file(kprobe_fd, "bpf_attach_kprobe").map(|fd| Kprobe { fd })
}

fn to_probe_attach_type(
  bpf_probe_attach_type: BpfProbeAttachType,
) -> raw_libbpf::bpf_probe_attach_type {
  match bpf_probe_attach_type {
    BpfProbeAttachType::Entry => raw_libbpf::bpf_probe_attach_type_BPF_PROBE_ENTRY,
    BpfProbeAttachType::Return => raw_libbpf::bpf_probe_attach_type_BPF_PROBE_RETURN,
  }
}

fn fd_to_file(fd: c_int, fn_name: &str) -> io::Result<File> {
  if fd >= 0 {
    let file = unsafe { File::from_raw_fd(fd) };
    Ok(file)
  } else if fd == -1 {
    Err(io::Error::last_os_error())
  } else {
    panic!("Unexpected value from {}(): {}", fn_name, fd)
  }
}
