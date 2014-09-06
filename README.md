authenc
=======

Standalone implemention of authenticated encryption algorithms.

## Compilation

authenc uses CMake for building:

```
mkdir build
cd build
cmake -DBACKEND=ref ..
make
```

This will build libauthenc.a and some test programs.
You can change the "ref" backend to any of the folders in src/ .
Currently there is:

* ref: naive C-only backend
* armv7-neon: ARMv7 speed-optimized with NEON; with side-channel resistance. Includes bitsliced AES by Bernstein and Schwabe.

You can skip CMake by simply building all the files in src/*, all the files in src/<backend>/*, and all the files
in src/ref/* which are listed in src/<backend>/CMakeLists.txt.

