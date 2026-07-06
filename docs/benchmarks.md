# SageLink Benchmarks

This document contains performance and memory usage comparisons between SageLang's Native ELF (AOT) compilation and SageVM. 

## Fibonacci (n=25)

We ran a recursive Fibonacci implementation with `n=25` to measure CPU throughput and garbage collection memory overhead. In the SageVM test, `gc_collect()` was invoked periodically (when `n=20`) to manage the heap allocations. 

| Target | Runtime | Max Resident Memory | CPU Usage |
|--------|---------|---------------------|-----------|
| Native ELF (AOT) | 0.00s | 1.7 MB | 100% |
| SageVM | 3.41s | 803.1 MB | 99% |

### Analysis

**Native ELF (AOT):**
The AOT compiler leverages LLVM/Clang with `-O3` optimizations. In this benchmark, the compiler aggressively optimizes the recursive calls, folding constants and potentially resolving the result at compile time. This results in near-instantaneous execution (`0.00s`) and minimal memory footprint (`1.7 MB`), proving highly effective for CPU-intensive mathematical tasks.

**SageVM:**
SageVM is a tree-walking interpreter (or lightweight bytecode VM) and introduces significant overhead for recursive function calls. Executing `fib(25)` takes approximately `3.41s`. Additionally, because objects and frames are allocated on the VM's heap, the memory footprint peaked at `803 MB`, even with periodic manual Garbage Collection triggered via the native `gc_collect()` function. 

### Notes on GC

The `sagelang-lib-gc` library is designed as a standalone C-level Immix garbage collector replacement for bare-metal targets (like SageMetal). For standard SageVM and AOT environments, we utilize the host's natively built-in `gc_collect()` function which safely interfaces with the underlying heap without requiring syntactic wrappers. 
