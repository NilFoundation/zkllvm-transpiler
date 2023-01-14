# Circuits Traspiler Library for =nil; Foundation's zkLLVM circuit compiler

[![Run tests](https://github.com/NilFoundation/zkllvm-transpiler/actions/workflows/run_tests.yml/badge.svg)](https://github.com/NilFoundation/zkllvm-transpiler/actions/workflows/run_tests.yml)

## Building

This library uses Boost CMake build modules (https://github.com/BoostCMake/cmake_modules.git).
To actually include this library in a project it is required to:

1. Add [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as submodule to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as submodules to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) (Look at [crypto3](https://github.com/nilfoundation/crypto3.git) for the example)

## Dependencies

### Internal

Crypto3 suite:

* [Crypto3.Algebra](https://github.com/nilfoundation/crypto3-algebra.git).
* [Crypto3.Math](https://github.com/nilfoundation/crypto3-math.git).
* [Crypto3.Multiprecision](https://github.com/nilfoundation/crypto3-multiprecision.git).
* [Crypto3.ZK](https://github.com/nilfoundation/crypto3-zk.git).

zkLLVM compiler ecosystem:

* [zkLLVM Assigner](https://github.com/NilFoundation/zkllvm-assigner.git).
* [zkLLVM Blueprint](https://github.com/NilFoundation/zkllvm-blueprint.git).
* [zkLLVM Compiler](https://github.com/NilFoundation/zkllvm-circifier.git).

### External
* [Boost](https://boost.org) (>= 1.76)
