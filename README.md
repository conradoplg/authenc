authenc
=======

Standalone implemention of authenticated encryption algorithms (currently only GCM).

## Compilation

authenc uses CMake for building:

```
mkdir build
cd build
cmake -DBACKEND=ref ..
make
```

This will build `libauthenc.a` and some test programs.
You can change the "ref" backend to any of the folders in `src/` .
Currently there is:

* ref: naive C-only backend
* armv7-neon: ARMv7 speed-optimized with NEON (VMULL.P8); with side-channel resistance. Includes bitsliced AES by Bernstein and Schwabe.
* armv8-aarch32-neon: 32-bit ARMv8 speed optimized with NEON (VMULL.P64) and AES instructions.
* armv8-aarch64-neon: 64-bit ARMv8 speed optimized with NEON (PMULL) and AES instructions.

You can skip CMake by simply building all the files in `src/`, all the files in `src/backend/`, and all the files
in `src/ref/` which are listed in `src/backend/CMakeLists.txt`.

## XCode

You'll need to create a project and include the files manually. Make sure to compile backend specific code with the corresponding
architecture. I'll eventually try to commit the project itself.


## Benchmark

A simple benchmark program is included in `bench/bench_ac_gcm.c`, which should be compiled in the `bench_ac_gcm` binary by CMake.

By default it uses `clock_gettime` to measure times. Change the `#define TIMER` in `bench/authenc_bench.c` to `MACH` in order to
use `mach_timebase_info` in iOS.

When running on the Galaxy Note 4 (or any big.LITTLE ARM processor), you can choose which core will run the benchmark by defining
`AUTHENC_BENCH_CORE` at the top `bench_ac_gcm.c` with the index of the core to run (e.g. `#define AUTHENC_BENCH_CORE 7`)


## License

MIT License, except benchmark code which was copied from RELIC and is LGPL, but it isn't compiled into the library.
