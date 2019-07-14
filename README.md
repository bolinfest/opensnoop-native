# opensnoop-native

This is a pure C implementation of [opensnoop](http://www.brendangregg.com/blog/2014-07-25/opensnoop-for-linux.html)
that uses [eBPF](https://lwn.net/Articles/740157/).
I put together a [detailed backstory](https://bolinfest.github.io/opensnoop-native/)
of how this came to be.

The ["official" version of opensnoop that uses eBPF](https://github.com/iovisor/bcc/blob/master/tools/opensnoop.py) is written
in Python, as it leverages the Python bindings from the
[BCC toolkit](https://github.com/iovisor/bcc) to dynamically generate
the eBPF program at _runtime_ by populating a template of C code
and compiling it on the fly into eBPF instructions.

This version of opensnoop differs slightly, as it uses the BCC
toolkit to generate a template for the eBPF program (as an array of eBPF
instructions) at _build time_ that can be populated directly in C.
Advantages:

- This implementation uses only libbpf at runtime whereas the original
  uses libbcc, which is a much larger dependency.
- Compared to the Python version, it eliminates some code that has
  to be duplicated between the Python code and C code template.
- It eliminates an extra division done in the eBPF program due to the
  limits of numeric precision in Python.
- Perhaps the most important difference (and the most subjective) is
  that this standalone version is _simpler_, which makes it easier to
  see what is going on. For example, because it is pure C, you can step
  through the entire program using `gdb`. Similarly, an `strace` of
  the pure C version is much cleaner compared to the original verison.
  When I first tried to understand how opensnoop worked, I had
  to navigate through several layers of code: the Python bindings for BCC,
  libbcc, and libbpf. In this implementation, you only need to worry
  about what libbpf is doing. Once you understand that, go back and see
  how those other layers make it easier to create tools that use eBPF.

## Build instructions

To build the program from scratch, you must have the BCC toolkit
installed:

```
$ ./build.sh
$ sudo ./opensnoop
```

If you want to leverage the existing code that was generated from
BCC (the generated code is checked into the repo to make it easier
for others to study and to build), then you can just do:

```
$ clang opensnoop.c -O3 -o opensnoop /usr/lib/x86_64-linux-gnu/libbpf.so
$ sudo ./opensnoop
```

In both cases, the version of libbpf/libbcc that you use should be
built from https://github.com/iovisor/bcc/commit/0354d767bbd3e30c6a9d4599d0fd07fee8f1337e
or later because that includes a critical fix that I landed to make
this code simpler to build.

## Quirks

Because the source code embeds the value of `LINUX_VERSION_CODE` from
`<linux/version.h>` into the final binary, a version that you build on
your machine will not work on a colleague's machine if they are not running
the exact same version of the kernel.
