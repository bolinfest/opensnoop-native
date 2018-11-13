// GENERATED FILE: See opensnoop.py.
extern crate libbpf;

use libbpf::BpfMap;

// pub const MAX_NUM_TRACE_ENTRY_INSTRUCTIONS: usize = 35;
pub const NUM_TRACE_ENTRY_INSTRUCTIONS: usize = 28;
// pub const NUM_TRACE_ENTRY_TID_INSTRUCTIONS: usize = 32;
// pub const NUM_TRACE_ENTRY_PID_INSTRUCTIONS: usize = 35;
pub const NUM_TRACE_RETURN_INSTRUCTIONS: usize = 82;
pub fn generate_trace_entry(instructions: &mut [libbpf::bpf_insn], fd3: &BpfMap) -> () {
  instructions[0] = libbpf::bpf_insn {
      code: 0x79,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(7, 1),
      off: 104,
      imm: 0,
  };
  instructions[1] = libbpf::bpf_insn {
      code: 0xb7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 0),
      off: 0,
      imm: 0,
  };
  instructions[2] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -8,
      imm: 0,
  };
  instructions[3] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -16,
      imm: 0,
  };
  instructions[4] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -24,
      imm: 0,
  };
  instructions[5] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -32,
      imm: 0,
  };
  instructions[6] = libbpf::bpf_insn {
      code: 0x85,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 14,
  };
  instructions[7] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(6, 0),
      off: 0,
      imm: 0,
  };
  instructions[8] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 6),
      off: -40,
      imm: 0,
  };
  instructions[9] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 10),
      off: 0,
      imm: 0,
  };
  instructions[10] = libbpf::bpf_insn {
      code: 0x7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 0),
      off: 0,
      imm: -24,
  };
  instructions[11] = libbpf::bpf_insn {
      code: 0xb7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(2, 0),
      off: 0,
      imm: 16,
  };
  instructions[12] = libbpf::bpf_insn {
      code: 0x85,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 16,
  };
  instructions[13] = libbpf::bpf_insn {
      code: 0x67,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 32,
  };
  instructions[14] = libbpf::bpf_insn {
      code: 0x77,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 32,
  };
  instructions[15] = libbpf::bpf_insn {
      code: 0x55,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 10,
      imm: 0,
  };
  instructions[16] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 7),
      off: -8,
      imm: 0,
  };
  instructions[17] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 6),
      off: -32,
      imm: 0,
  };
  instructions[18] = libbpf::bpf_insn {
      code: 0x18,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 1),
      off: 0,
      imm: fd3.fd(),
  };
  instructions[19] = libbpf::bpf_insn {
      code: 0x0,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 0,
  };
  instructions[20] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(2, 10),
      off: 0,
      imm: 0,
  };
  instructions[21] = libbpf::bpf_insn {
      code: 0x7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(2, 0),
      off: 0,
      imm: -40,
  };
  instructions[22] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(3, 10),
      off: 0,
      imm: 0,
  };
  instructions[23] = libbpf::bpf_insn {
      code: 0x7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(3, 0),
      off: 0,
      imm: -32,
  };
  instructions[24] = libbpf::bpf_insn {
      code: 0xb7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(4, 0),
      off: 0,
      imm: 0,
  };
  instructions[25] = libbpf::bpf_insn {
      code: 0x85,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 2,
  };
  instructions[26] = libbpf::bpf_insn {
      code: 0xb7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 0,
  };
  instructions[27] = libbpf::bpf_insn {
      code: 0x95,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 0,
  };
}

pub fn generate_trace_return(instructions: &mut [libbpf::bpf_insn], fd3: &BpfMap, fd4: &BpfMap) -> () {
  instructions[0] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(6, 1),
      off: 0,
      imm: 0,
  };
  instructions[1] = libbpf::bpf_insn {
      code: 0x85,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 14,
  };
  instructions[2] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 0),
      off: -8,
      imm: 0,
  };
  instructions[3] = libbpf::bpf_insn {
      code: 0xb7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 0),
      off: 0,
      imm: 0,
  };
  instructions[4] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -16,
      imm: 0,
  };
  instructions[5] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -24,
      imm: 0,
  };
  instructions[6] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -32,
      imm: 0,
  };
  instructions[7] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -40,
      imm: 0,
  };
  instructions[8] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -48,
      imm: 0,
  };
  instructions[9] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -56,
      imm: 0,
  };
  instructions[10] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -64,
      imm: 0,
  };
  instructions[11] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -72,
      imm: 0,
  };
  instructions[12] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -80,
      imm: 0,
  };
  instructions[13] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -88,
      imm: 0,
  };
  instructions[14] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -96,
      imm: 0,
  };
  instructions[15] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -104,
      imm: 0,
  };
  instructions[16] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -112,
      imm: 0,
  };
  instructions[17] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -120,
      imm: 0,
  };
  instructions[18] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -128,
      imm: 0,
  };
  instructions[19] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -136,
      imm: 0,
  };
  instructions[20] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -144,
      imm: 0,
  };
  instructions[21] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -152,
      imm: 0,
  };
  instructions[22] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -160,
      imm: 0,
  };
  instructions[23] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -168,
      imm: 0,
  };
  instructions[24] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -176,
      imm: 0,
  };
  instructions[25] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -184,
      imm: 0,
  };
  instructions[26] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -192,
      imm: 0,
  };
  instructions[27] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -200,
      imm: 0,
  };
  instructions[28] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -208,
      imm: 0,
  };
  instructions[29] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -216,
      imm: 0,
  };
  instructions[30] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -224,
      imm: 0,
  };
  instructions[31] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -232,
      imm: 0,
  };
  instructions[32] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -240,
      imm: 0,
  };
  instructions[33] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -248,
      imm: 0,
  };
  instructions[34] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -256,
      imm: 0,
  };
  instructions[35] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -264,
      imm: 0,
  };
  instructions[36] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -272,
      imm: 0,
  };
  instructions[37] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -280,
      imm: 0,
  };
  instructions[38] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -288,
      imm: 0,
  };
  instructions[39] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -296,
      imm: 0,
  };
  instructions[40] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -304,
      imm: 0,
  };
  instructions[41] = libbpf::bpf_insn {
      code: 0x85,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 5,
  };
  instructions[42] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(7, 0),
      off: 0,
      imm: 0,
  };
  instructions[43] = libbpf::bpf_insn {
      code: 0x18,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 1),
      off: 0,
      imm: fd3.fd(),
  };
  instructions[44] = libbpf::bpf_insn {
      code: 0x0,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 0,
  };
  instructions[45] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(2, 10),
      off: 0,
      imm: 0,
  };
  instructions[46] = libbpf::bpf_insn {
      code: 0x7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(2, 0),
      off: 0,
      imm: -8,
  };
  instructions[47] = libbpf::bpf_insn {
      code: 0x85,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 1,
  };
  instructions[48] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(8, 0),
      off: 0,
      imm: 0,
  };
  instructions[49] = libbpf::bpf_insn {
      code: 0x15,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(8, 0),
      off: 30,
      imm: 0,
  };
  instructions[50] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(3, 8),
      off: 0,
      imm: 0,
  };
  instructions[51] = libbpf::bpf_insn {
      code: 0x7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(3, 0),
      off: 0,
      imm: 8,
  };
  instructions[52] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 10),
      off: 0,
      imm: 0,
  };
  instructions[53] = libbpf::bpf_insn {
      code: 0x7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 0),
      off: 0,
      imm: -284,
  };
  instructions[54] = libbpf::bpf_insn {
      code: 0xb7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(2, 0),
      off: 0,
      imm: 16,
  };
  instructions[55] = libbpf::bpf_insn {
      code: 0x85,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 4,
  };
  instructions[56] = libbpf::bpf_insn {
      code: 0x79,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(3, 8),
      off: 24,
      imm: 0,
  };
  instructions[57] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 10),
      off: 0,
      imm: 0,
  };
  instructions[58] = libbpf::bpf_insn {
      code: 0x7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 0),
      off: 0,
      imm: -268,
  };
  instructions[59] = libbpf::bpf_insn {
      code: 0xb7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(2, 0),
      off: 0,
      imm: 255,
  };
  instructions[60] = libbpf::bpf_insn {
      code: 0x85,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 4,
  };
  instructions[61] = libbpf::bpf_insn {
      code: 0x79,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 8),
      off: 0,
      imm: 0,
  };
  instructions[62] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 7),
      off: -296,
      imm: 0,
  };
  instructions[63] = libbpf::bpf_insn {
      code: 0x7b,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -304,
      imm: 0,
  };
  instructions[64] = libbpf::bpf_insn {
      code: 0x79,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 6),
      off: 80,
      imm: 0,
  };
  instructions[65] = libbpf::bpf_insn {
      code: 0x63,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(10, 1),
      off: -288,
      imm: 0,
  };
  instructions[66] = libbpf::bpf_insn {
      code: 0x18,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(2, 1),
      off: 0,
      imm: fd4.fd(),
  };
  instructions[67] = libbpf::bpf_insn {
      code: 0x0,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 0,
  };
  instructions[68] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(4, 10),
      off: 0,
      imm: 0,
  };
  instructions[69] = libbpf::bpf_insn {
      code: 0x7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(4, 0),
      off: 0,
      imm: -304,
  };
  instructions[70] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 6),
      off: 0,
      imm: 0,
  };
  instructions[71] = libbpf::bpf_insn {
      code: 0x18,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(3, 0),
      off: 0,
      imm: -1,
  };
  instructions[72] = libbpf::bpf_insn {
      code: 0x0,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 0,
  };
  instructions[73] = libbpf::bpf_insn {
      code: 0xb7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(5, 0),
      off: 0,
      imm: 296,
  };
  instructions[74] = libbpf::bpf_insn {
      code: 0x85,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 25,
  };
  instructions[75] = libbpf::bpf_insn {
      code: 0x18,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(1, 1),
      off: 0,
      imm: fd3.fd(),
  };
  instructions[76] = libbpf::bpf_insn {
      code: 0x0,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 0,
  };
  instructions[77] = libbpf::bpf_insn {
      code: 0xbf,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(2, 10),
      off: 0,
      imm: 0,
  };
  instructions[78] = libbpf::bpf_insn {
      code: 0x7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(2, 0),
      off: 0,
      imm: -8,
  };
  instructions[79] = libbpf::bpf_insn {
      code: 0x85,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 3,
  };
  instructions[80] = libbpf::bpf_insn {
      code: 0xb7,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 0,
  };
  instructions[81] = libbpf::bpf_insn {
      code: 0x95,
      _bitfield_1: libbpf::bpf_insn::new_bitfield_1(0, 0),
      off: 0,
      imm: 0,
  };
}

