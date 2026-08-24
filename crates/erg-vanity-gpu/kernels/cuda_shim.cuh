// cuda_shim.cuh - OpenCL C compatibility layer for compiling the erg-vanity-gpu
// kernel sources with nvcc. One source, two compilers.
#pragma once

#include <cstdint>

typedef unsigned char uchar;
typedef unsigned int uint;
// NOTE: `ulong` comes from <sys/types.h> (unsigned long, 64-bit on LP64) - do not
// redeclare. All kernel arithmetic uses explicit ull literals, so the underlying
// type is irrelevant as long as it is 64-bit.

// OpenCL vector type used by the kernels. Field names match .s0-.s7 swizzles.
struct ulong8 {
    ulong s0, s1, s2, s3, s4, s5, s6, s7;
};
__host__ __device__ inline ulong8 make_ulong8(ulong s0, ulong s1, ulong s2, ulong s3,
                                              ulong s4, ulong s5, ulong s6, ulong s7) {
    return ulong8{s0, s1, s2, s3, s4, s5, s6, s7};
}
__host__ __device__ inline ulong8 operator^(const ulong8& a, const ulong8& b) {
    return make_ulong8(a.s0^b.s0, a.s1^b.s1, a.s2^b.s2, a.s3^b.s3,
                       a.s4^b.s4, a.s5^b.s5, a.s6^b.s6, a.s7^b.s7);
}

// Work-item geometry (1D launches only; matches production usage).
__device__ inline uint get_global_id(uint dim) {
    (void)dim;
    return blockIdx.x * blockDim.x + threadIdx.x;
}
__device__ inline uint get_local_id(uint dim) { (void)dim; return threadIdx.x; }
__device__ inline uint get_local_size(uint dim) { (void)dim; return blockDim.x; }

// Address-space qualifiers: pointers are generic in CUDA.
#define __global
#define __local
#define __private
#define __kernel extern "C" __global__

// atomic_inc returns the OLD value, like OpenCL.
__device__ inline int atomic_inc(volatile int* p) { return atomicAdd(const_cast<int*>(p), 1); }
__device__ inline uint atomic_inc(volatile uint* p) { return atomicAdd(const_cast<uint*>(p), 1u); }

// OpenCL rotate() is a LEFT rotate by n mod N bits.
__device__ inline ulong rotate(ulong x, ulong n) {
    n &= 63ull;
    return (x << n) | (x >> ((64ull - n) & 63ull));
}
__device__ inline uint rotate(uint x, uint n) {
    n &= 31u;
    return (x << n) | (x >> ((32u - n) & 31u));
}
