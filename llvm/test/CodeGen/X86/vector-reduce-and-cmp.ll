; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=+sse2 | FileCheck %s --check-prefixes=SSE,SSE2
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=+sse4.1 | FileCheck %s --check-prefixes=SSE,SSE41
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=+avx | FileCheck %s --check-prefixes=AVX,AVX1OR2,AVX1
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=+avx2 | FileCheck %s --check-prefixes=AVX,AVX1OR2,AVX2
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=+avx512f | FileCheck %s --check-prefixes=AVX,AVX512,AVX512F
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=+avx512f,+avx512bw | FileCheck %s --check-prefixes=AVX,AVX512,AVX512BW
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=+avx512f,+avx512bw,+avx512vl | FileCheck %s --check-prefixes=AVX,AVX512,AVX512BWVL

;
; vXi64
;

define i1 @test_v2i64(<2 x i64> %a0) {
; SSE2-LABEL: test_v2i64:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqd %xmm0, %xmm1
; SSE2-NEXT:    movmskps %xmm1, %eax
; SSE2-NEXT:    xorl $15, %eax
; SSE2-NEXT:    sete %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v2i64:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setb %al
; SSE41-NEXT:    retq
;
; AVX-LABEL: test_v2i64:
; AVX:       # %bb.0:
; AVX-NEXT:    vpcmpeqd %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vptest %xmm1, %xmm0
; AVX-NEXT:    setb %al
; AVX-NEXT:    retq
  %1 = call i64 @llvm.vector.reduce.and.v2i64(<2 x i64> %a0)
  %2 = icmp eq i64 %1, -1
  ret i1 %2
}

define i1 @test_v4i64(<4 x i64> %a0) {
; SSE2-LABEL: test_v4i64:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqd %xmm0, %xmm1
; SSE2-NEXT:    movmskps %xmm1, %eax
; SSE2-NEXT:    xorl $15, %eax
; SSE2-NEXT:    setne %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v4i64:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setae %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v4i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setae %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v4i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setae %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v4i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX512-NEXT:    vptest %ymm1, %ymm0
; AVX512-NEXT:    setae %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i64 @llvm.vector.reduce.and.v4i64(<4 x i64> %a0)
  %2 = icmp ne i64 %1, -1
  ret i1 %2
}

define i1 @test_v8i64(<8 x i64> %a0) {
; SSE2-LABEL: test_v8i64:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm3, %xmm1
; SSE2-NEXT:    pand %xmm2, %xmm0
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqd %xmm0, %xmm1
; SSE2-NEXT:    movmskps %xmm1, %eax
; SSE2-NEXT:    xorl $15, %eax
; SSE2-NEXT:    sete %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v8i64:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm3, %xmm1
; SSE41-NEXT:    pand %xmm2, %xmm0
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setb %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v8i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vandps %ymm1, %ymm0, %ymm0
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setb %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v8i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpand %ymm1, %ymm0, %ymm0
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setb %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v8i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpternlogd {{.*#+}} zmm1 = -1
; AVX512-NEXT:    vpcmpneqd %zmm1, %zmm0, %k0
; AVX512-NEXT:    kortestw %k0, %k0
; AVX512-NEXT:    sete %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i64 @llvm.vector.reduce.and.v8i64(<8 x i64> %a0)
  %2 = icmp eq i64 %1, -1
  ret i1 %2
}

define i1 @test_v16i64(<16 x i64> %a0) {
; SSE2-LABEL: test_v16i64:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm7, %xmm3
; SSE2-NEXT:    pand %xmm5, %xmm1
; SSE2-NEXT:    pand %xmm3, %xmm1
; SSE2-NEXT:    pand %xmm6, %xmm2
; SSE2-NEXT:    pand %xmm4, %xmm0
; SSE2-NEXT:    pand %xmm2, %xmm0
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqd %xmm0, %xmm1
; SSE2-NEXT:    movmskps %xmm1, %eax
; SSE2-NEXT:    xorl $15, %eax
; SSE2-NEXT:    setne %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v16i64:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm7, %xmm3
; SSE41-NEXT:    pand %xmm5, %xmm1
; SSE41-NEXT:    pand %xmm3, %xmm1
; SSE41-NEXT:    pand %xmm6, %xmm2
; SSE41-NEXT:    pand %xmm4, %xmm0
; SSE41-NEXT:    pand %xmm2, %xmm0
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setae %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v16i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vandps %ymm3, %ymm1, %ymm1
; AVX1-NEXT:    vandps %ymm2, %ymm0, %ymm0
; AVX1-NEXT:    vandps %ymm1, %ymm0, %ymm0
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setae %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v16i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpand %ymm3, %ymm1, %ymm1
; AVX2-NEXT:    vpand %ymm2, %ymm0, %ymm0
; AVX2-NEXT:    vpand %ymm1, %ymm0, %ymm0
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setae %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v16i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpandq %zmm1, %zmm0, %zmm0
; AVX512-NEXT:    vpternlogd {{.*#+}} zmm1 = -1
; AVX512-NEXT:    vpcmpneqd %zmm1, %zmm0, %k0
; AVX512-NEXT:    kortestw %k0, %k0
; AVX512-NEXT:    setne %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i64 @llvm.vector.reduce.and.v16i64(<16 x i64> %a0)
  %2 = icmp ne i64 %1, -1
  ret i1 %2
}

;
; vXi32
;

define i1 @test_v2i32(<2 x i32> %a0) {
; SSE-LABEL: test_v2i32:
; SSE:       # %bb.0:
; SSE-NEXT:    movq %xmm0, %rax
; SSE-NEXT:    cmpq $-1, %rax
; SSE-NEXT:    sete %al
; SSE-NEXT:    retq
;
; AVX-LABEL: test_v2i32:
; AVX:       # %bb.0:
; AVX-NEXT:    vmovq %xmm0, %rax
; AVX-NEXT:    cmpq $-1, %rax
; AVX-NEXT:    sete %al
; AVX-NEXT:    retq
  %1 = call i32 @llvm.vector.reduce.and.v2i32(<2 x i32> %a0)
  %2 = icmp eq i32 %1, -1
  ret i1 %2
}

define i1 @test_v4i32(<4 x i32> %a0) {
; SSE2-LABEL: test_v4i32:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqd %xmm0, %xmm1
; SSE2-NEXT:    movmskps %xmm1, %eax
; SSE2-NEXT:    xorl $15, %eax
; SSE2-NEXT:    setne %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v4i32:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setae %al
; SSE41-NEXT:    retq
;
; AVX-LABEL: test_v4i32:
; AVX:       # %bb.0:
; AVX-NEXT:    vpcmpeqd %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vptest %xmm1, %xmm0
; AVX-NEXT:    setae %al
; AVX-NEXT:    retq
  %1 = call i32 @llvm.vector.reduce.and.v4i32(<4 x i32> %a0)
  %2 = icmp ne i32 %1, -1
  ret i1 %2
}

define i1 @test_v8i32(<8 x i32> %a0) {
; SSE2-LABEL: test_v8i32:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqd %xmm0, %xmm1
; SSE2-NEXT:    movmskps %xmm1, %eax
; SSE2-NEXT:    xorl $15, %eax
; SSE2-NEXT:    sete %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v8i32:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setb %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v8i32:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setb %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v8i32:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setb %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v8i32:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX512-NEXT:    vptest %ymm1, %ymm0
; AVX512-NEXT:    setb %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i32 @llvm.vector.reduce.and.v8i32(<8 x i32> %a0)
  %2 = icmp eq i32 %1, -1
  ret i1 %2
}

define i1 @test_v16i32(<16 x i32> %a0) {
; SSE2-LABEL: test_v16i32:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm3, %xmm1
; SSE2-NEXT:    pand %xmm2, %xmm0
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqd %xmm0, %xmm1
; SSE2-NEXT:    movmskps %xmm1, %eax
; SSE2-NEXT:    xorl $15, %eax
; SSE2-NEXT:    setne %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v16i32:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm3, %xmm1
; SSE41-NEXT:    pand %xmm2, %xmm0
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setae %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v16i32:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vandps %ymm1, %ymm0, %ymm0
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setae %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v16i32:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpand %ymm1, %ymm0, %ymm0
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setae %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v16i32:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpternlogd {{.*#+}} zmm1 = -1
; AVX512-NEXT:    vpcmpneqd %zmm1, %zmm0, %k0
; AVX512-NEXT:    kortestw %k0, %k0
; AVX512-NEXT:    setne %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i32 @llvm.vector.reduce.and.v16i32(<16 x i32> %a0)
  %2 = icmp ne i32 %1, -1
  ret i1 %2
}

define i1 @test_v32i32(<32 x i32> %a0) {
; SSE2-LABEL: test_v32i32:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm7, %xmm3
; SSE2-NEXT:    pand %xmm5, %xmm1
; SSE2-NEXT:    pand %xmm3, %xmm1
; SSE2-NEXT:    pand %xmm6, %xmm2
; SSE2-NEXT:    pand %xmm4, %xmm0
; SSE2-NEXT:    pand %xmm2, %xmm0
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqd %xmm0, %xmm1
; SSE2-NEXT:    movmskps %xmm1, %eax
; SSE2-NEXT:    xorl $15, %eax
; SSE2-NEXT:    sete %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v32i32:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm7, %xmm3
; SSE41-NEXT:    pand %xmm5, %xmm1
; SSE41-NEXT:    pand %xmm3, %xmm1
; SSE41-NEXT:    pand %xmm6, %xmm2
; SSE41-NEXT:    pand %xmm4, %xmm0
; SSE41-NEXT:    pand %xmm2, %xmm0
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setb %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v32i32:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vandps %ymm3, %ymm1, %ymm1
; AVX1-NEXT:    vandps %ymm2, %ymm0, %ymm0
; AVX1-NEXT:    vandps %ymm1, %ymm0, %ymm0
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setb %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v32i32:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpand %ymm3, %ymm1, %ymm1
; AVX2-NEXT:    vpand %ymm2, %ymm0, %ymm0
; AVX2-NEXT:    vpand %ymm1, %ymm0, %ymm0
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setb %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v32i32:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpandd %zmm1, %zmm0, %zmm0
; AVX512-NEXT:    vpternlogd {{.*#+}} zmm1 = -1
; AVX512-NEXT:    vpcmpneqd %zmm1, %zmm0, %k0
; AVX512-NEXT:    kortestw %k0, %k0
; AVX512-NEXT:    sete %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i32 @llvm.vector.reduce.and.v32i32(<32 x i32> %a0)
  %2 = icmp eq i32 %1, -1
  ret i1 %2
}

;
; vXi16
;

define i1 @test_v2i16(<2 x i16> %a0) {
; SSE-LABEL: test_v2i16:
; SSE:       # %bb.0:
; SSE-NEXT:    movd %xmm0, %eax
; SSE-NEXT:    cmpl $-1, %eax
; SSE-NEXT:    sete %al
; SSE-NEXT:    retq
;
; AVX-LABEL: test_v2i16:
; AVX:       # %bb.0:
; AVX-NEXT:    vmovd %xmm0, %eax
; AVX-NEXT:    cmpl $-1, %eax
; AVX-NEXT:    sete %al
; AVX-NEXT:    retq
  %1 = call i16 @llvm.vector.reduce.and.v2i16(<2 x i16> %a0)
  %2 = icmp eq i16 %1, -1
  ret i1 %2
}

define i1 @test_v4i16(<4 x i16> %a0) {
; SSE-LABEL: test_v4i16:
; SSE:       # %bb.0:
; SSE-NEXT:    movq %xmm0, %rax
; SSE-NEXT:    cmpq $-1, %rax
; SSE-NEXT:    setne %al
; SSE-NEXT:    retq
;
; AVX-LABEL: test_v4i16:
; AVX:       # %bb.0:
; AVX-NEXT:    vmovq %xmm0, %rax
; AVX-NEXT:    cmpq $-1, %rax
; AVX-NEXT:    setne %al
; AVX-NEXT:    retq
  %1 = call i16 @llvm.vector.reduce.and.v4i16(<4 x i16> %a0)
  %2 = icmp ne i16 %1, -1
  ret i1 %2
}

define i1 @test_v8i16(<8 x i16> %a0) {
; SSE2-LABEL: test_v8i16:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqb %xmm0, %xmm1
; SSE2-NEXT:    pmovmskb %xmm1, %eax
; SSE2-NEXT:    xorl $65535, %eax # imm = 0xFFFF
; SSE2-NEXT:    sete %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v8i16:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setb %al
; SSE41-NEXT:    retq
;
; AVX-LABEL: test_v8i16:
; AVX:       # %bb.0:
; AVX-NEXT:    vpcmpeqd %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vptest %xmm1, %xmm0
; AVX-NEXT:    setb %al
; AVX-NEXT:    retq
  %1 = call i16 @llvm.vector.reduce.and.v8i16(<8 x i16> %a0)
  %2 = icmp eq i16 %1, -1
  ret i1 %2
}

define i1 @test_v16i16(<16 x i16> %a0) {
; SSE2-LABEL: test_v16i16:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqb %xmm0, %xmm1
; SSE2-NEXT:    pmovmskb %xmm1, %eax
; SSE2-NEXT:    xorl $65535, %eax # imm = 0xFFFF
; SSE2-NEXT:    setne %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v16i16:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setae %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v16i16:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setae %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v16i16:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setae %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v16i16:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX512-NEXT:    vptest %ymm1, %ymm0
; AVX512-NEXT:    setae %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i16 @llvm.vector.reduce.and.v16i16(<16 x i16> %a0)
  %2 = icmp ne i16 %1, -1
  ret i1 %2
}

define i1 @test_v32i16(<32 x i16> %a0) {
; SSE2-LABEL: test_v32i16:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm3, %xmm1
; SSE2-NEXT:    pand %xmm2, %xmm0
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqb %xmm0, %xmm1
; SSE2-NEXT:    pmovmskb %xmm1, %eax
; SSE2-NEXT:    xorl $65535, %eax # imm = 0xFFFF
; SSE2-NEXT:    sete %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v32i16:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm3, %xmm1
; SSE41-NEXT:    pand %xmm2, %xmm0
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setb %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v32i16:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vandps %ymm1, %ymm0, %ymm0
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setb %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v32i16:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpand %ymm1, %ymm0, %ymm0
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setb %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v32i16:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpternlogd {{.*#+}} zmm1 = -1
; AVX512-NEXT:    vpcmpneqd %zmm1, %zmm0, %k0
; AVX512-NEXT:    kortestw %k0, %k0
; AVX512-NEXT:    sete %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i16 @llvm.vector.reduce.and.v32i16(<32 x i16> %a0)
  %2 = icmp eq i16 %1, -1
  ret i1 %2
}

define i1 @test_v64i16(<64 x i16> %a0) {
; SSE2-LABEL: test_v64i16:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm7, %xmm3
; SSE2-NEXT:    pand %xmm5, %xmm1
; SSE2-NEXT:    pand %xmm3, %xmm1
; SSE2-NEXT:    pand %xmm6, %xmm2
; SSE2-NEXT:    pand %xmm4, %xmm0
; SSE2-NEXT:    pand %xmm2, %xmm0
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqb %xmm0, %xmm1
; SSE2-NEXT:    pmovmskb %xmm1, %eax
; SSE2-NEXT:    xorl $65535, %eax # imm = 0xFFFF
; SSE2-NEXT:    setne %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v64i16:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm7, %xmm3
; SSE41-NEXT:    pand %xmm5, %xmm1
; SSE41-NEXT:    pand %xmm3, %xmm1
; SSE41-NEXT:    pand %xmm6, %xmm2
; SSE41-NEXT:    pand %xmm4, %xmm0
; SSE41-NEXT:    pand %xmm2, %xmm0
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setae %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v64i16:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vandps %ymm3, %ymm1, %ymm1
; AVX1-NEXT:    vandps %ymm2, %ymm0, %ymm0
; AVX1-NEXT:    vandps %ymm1, %ymm0, %ymm0
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setae %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v64i16:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpand %ymm3, %ymm1, %ymm1
; AVX2-NEXT:    vpand %ymm2, %ymm0, %ymm0
; AVX2-NEXT:    vpand %ymm1, %ymm0, %ymm0
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setae %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v64i16:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpandq %zmm1, %zmm0, %zmm0
; AVX512-NEXT:    vpternlogd {{.*#+}} zmm1 = -1
; AVX512-NEXT:    vpcmpneqd %zmm1, %zmm0, %k0
; AVX512-NEXT:    kortestw %k0, %k0
; AVX512-NEXT:    setne %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i16 @llvm.vector.reduce.and.v64i16(<64 x i16> %a0)
  %2 = icmp ne i16 %1, -1
  ret i1 %2
}

;
; vXi8
;

define i1 @test_v2i8(<2 x i8> %a0) {
; SSE-LABEL: test_v2i8:
; SSE:       # %bb.0:
; SSE-NEXT:    movd %xmm0, %eax
; SSE-NEXT:    cmpw $-1, %ax
; SSE-NEXT:    sete %al
; SSE-NEXT:    retq
;
; AVX-LABEL: test_v2i8:
; AVX:       # %bb.0:
; AVX-NEXT:    vmovd %xmm0, %eax
; AVX-NEXT:    cmpw $-1, %ax
; AVX-NEXT:    sete %al
; AVX-NEXT:    retq
  %1 = call i8 @llvm.vector.reduce.and.v2i8(<2 x i8> %a0)
  %2 = icmp eq i8 %1, -1
  ret i1 %2
}

define i1 @test_v4i8(<4 x i8> %a0) {
; SSE-LABEL: test_v4i8:
; SSE:       # %bb.0:
; SSE-NEXT:    movd %xmm0, %eax
; SSE-NEXT:    cmpl $-1, %eax
; SSE-NEXT:    setne %al
; SSE-NEXT:    retq
;
; AVX-LABEL: test_v4i8:
; AVX:       # %bb.0:
; AVX-NEXT:    vmovd %xmm0, %eax
; AVX-NEXT:    cmpl $-1, %eax
; AVX-NEXT:    setne %al
; AVX-NEXT:    retq
  %1 = call i8 @llvm.vector.reduce.and.v4i8(<4 x i8> %a0)
  %2 = icmp ne i8 %1, -1
  ret i1 %2
}

define i1 @test_v8i8(<8 x i8> %a0) {
; SSE-LABEL: test_v8i8:
; SSE:       # %bb.0:
; SSE-NEXT:    movq %xmm0, %rax
; SSE-NEXT:    cmpq $-1, %rax
; SSE-NEXT:    sete %al
; SSE-NEXT:    retq
;
; AVX-LABEL: test_v8i8:
; AVX:       # %bb.0:
; AVX-NEXT:    vmovq %xmm0, %rax
; AVX-NEXT:    cmpq $-1, %rax
; AVX-NEXT:    sete %al
; AVX-NEXT:    retq
  %1 = call i8 @llvm.vector.reduce.and.v8i8(<8 x i8> %a0)
  %2 = icmp eq i8 %1, -1
  ret i1 %2
}

define i1 @test_v16i8(<16 x i8> %a0) {
; SSE2-LABEL: test_v16i8:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqb %xmm0, %xmm1
; SSE2-NEXT:    pmovmskb %xmm1, %eax
; SSE2-NEXT:    xorl $65535, %eax # imm = 0xFFFF
; SSE2-NEXT:    setne %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v16i8:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setae %al
; SSE41-NEXT:    retq
;
; AVX-LABEL: test_v16i8:
; AVX:       # %bb.0:
; AVX-NEXT:    vpcmpeqd %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vptest %xmm1, %xmm0
; AVX-NEXT:    setae %al
; AVX-NEXT:    retq
  %1 = call i8 @llvm.vector.reduce.and.v16i8(<16 x i8> %a0)
  %2 = icmp ne i8 %1, -1
  ret i1 %2
}

define i1 @test_v32i8(<32 x i8> %a0) {
; SSE2-LABEL: test_v32i8:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqb %xmm0, %xmm1
; SSE2-NEXT:    pmovmskb %xmm1, %eax
; SSE2-NEXT:    xorl $65535, %eax # imm = 0xFFFF
; SSE2-NEXT:    sete %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v32i8:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setb %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v32i8:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setb %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v32i8:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setb %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v32i8:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX512-NEXT:    vptest %ymm1, %ymm0
; AVX512-NEXT:    setb %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i8 @llvm.vector.reduce.and.v32i8(<32 x i8> %a0)
  %2 = icmp eq i8 %1, -1
  ret i1 %2
}

define i1 @test_v64i8(<64 x i8> %a0) {
; SSE2-LABEL: test_v64i8:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm3, %xmm1
; SSE2-NEXT:    pand %xmm2, %xmm0
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqb %xmm0, %xmm1
; SSE2-NEXT:    pmovmskb %xmm1, %eax
; SSE2-NEXT:    xorl $65535, %eax # imm = 0xFFFF
; SSE2-NEXT:    setne %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v64i8:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm3, %xmm1
; SSE41-NEXT:    pand %xmm2, %xmm0
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setae %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v64i8:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vandps %ymm1, %ymm0, %ymm0
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setae %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v64i8:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpand %ymm1, %ymm0, %ymm0
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setae %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v64i8:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpternlogd {{.*#+}} zmm1 = -1
; AVX512-NEXT:    vpcmpneqd %zmm1, %zmm0, %k0
; AVX512-NEXT:    kortestw %k0, %k0
; AVX512-NEXT:    setne %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i8 @llvm.vector.reduce.and.v64i8(<64 x i8> %a0)
  %2 = icmp ne i8 %1, -1
  ret i1 %2
}

define i1 @test_v128i8(<128 x i8> %a0) {
; SSE2-LABEL: test_v128i8:
; SSE2:       # %bb.0:
; SSE2-NEXT:    pand %xmm7, %xmm3
; SSE2-NEXT:    pand %xmm5, %xmm1
; SSE2-NEXT:    pand %xmm3, %xmm1
; SSE2-NEXT:    pand %xmm6, %xmm2
; SSE2-NEXT:    pand %xmm4, %xmm0
; SSE2-NEXT:    pand %xmm2, %xmm0
; SSE2-NEXT:    pand %xmm1, %xmm0
; SSE2-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE2-NEXT:    pcmpeqb %xmm0, %xmm1
; SSE2-NEXT:    pmovmskb %xmm1, %eax
; SSE2-NEXT:    xorl $65535, %eax # imm = 0xFFFF
; SSE2-NEXT:    sete %al
; SSE2-NEXT:    retq
;
; SSE41-LABEL: test_v128i8:
; SSE41:       # %bb.0:
; SSE41-NEXT:    pand %xmm7, %xmm3
; SSE41-NEXT:    pand %xmm5, %xmm1
; SSE41-NEXT:    pand %xmm3, %xmm1
; SSE41-NEXT:    pand %xmm6, %xmm2
; SSE41-NEXT:    pand %xmm4, %xmm0
; SSE41-NEXT:    pand %xmm2, %xmm0
; SSE41-NEXT:    pand %xmm1, %xmm0
; SSE41-NEXT:    pcmpeqd %xmm1, %xmm1
; SSE41-NEXT:    ptest %xmm1, %xmm0
; SSE41-NEXT:    setb %al
; SSE41-NEXT:    retq
;
; AVX1-LABEL: test_v128i8:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vandps %ymm3, %ymm1, %ymm1
; AVX1-NEXT:    vandps %ymm2, %ymm0, %ymm0
; AVX1-NEXT:    vandps %ymm1, %ymm0, %ymm0
; AVX1-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX1-NEXT:    vcmptrueps %ymm1, %ymm1, %ymm1
; AVX1-NEXT:    vptest %ymm1, %ymm0
; AVX1-NEXT:    setb %al
; AVX1-NEXT:    vzeroupper
; AVX1-NEXT:    retq
;
; AVX2-LABEL: test_v128i8:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpand %ymm3, %ymm1, %ymm1
; AVX2-NEXT:    vpand %ymm2, %ymm0, %ymm0
; AVX2-NEXT:    vpand %ymm1, %ymm0, %ymm0
; AVX2-NEXT:    vpcmpeqd %ymm1, %ymm1, %ymm1
; AVX2-NEXT:    vptest %ymm1, %ymm0
; AVX2-NEXT:    setb %al
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
;
; AVX512-LABEL: test_v128i8:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpandq %zmm1, %zmm0, %zmm0
; AVX512-NEXT:    vpternlogd {{.*#+}} zmm1 = -1
; AVX512-NEXT:    vpcmpneqd %zmm1, %zmm0, %k0
; AVX512-NEXT:    kortestw %k0, %k0
; AVX512-NEXT:    sete %al
; AVX512-NEXT:    vzeroupper
; AVX512-NEXT:    retq
  %1 = call i8 @llvm.vector.reduce.and.v128i8(<128 x i8> %a0)
  %2 = icmp eq i8 %1, -1
  ret i1 %2
}

declare i64 @llvm.vector.reduce.and.v2i64(<2 x i64>)
declare i64 @llvm.vector.reduce.and.v4i64(<4 x i64>)
declare i64 @llvm.vector.reduce.and.v8i64(<8 x i64>)
declare i64 @llvm.vector.reduce.and.v16i64(<16 x i64>)

declare i32 @llvm.vector.reduce.and.v2i32(<2 x i32>)
declare i32 @llvm.vector.reduce.and.v4i32(<4 x i32>)
declare i32 @llvm.vector.reduce.and.v8i32(<8 x i32>)
declare i32 @llvm.vector.reduce.and.v16i32(<16 x i32>)
declare i32 @llvm.vector.reduce.and.v32i32(<32 x i32>)

declare i16 @llvm.vector.reduce.and.v2i16(<2 x i16>)
declare i16 @llvm.vector.reduce.and.v4i16(<4 x i16>)
declare i16 @llvm.vector.reduce.and.v8i16(<8 x i16>)
declare i16 @llvm.vector.reduce.and.v16i16(<16 x i16>)
declare i16 @llvm.vector.reduce.and.v32i16(<32 x i16>)
declare i16 @llvm.vector.reduce.and.v64i16(<64 x i16>)

declare i8 @llvm.vector.reduce.and.v2i8(<2 x i8>)
declare i8 @llvm.vector.reduce.and.v4i8(<4 x i8>)
declare i8 @llvm.vector.reduce.and.v8i8(<8 x i8>)
declare i8 @llvm.vector.reduce.and.v16i8(<16 x i8>)
declare i8 @llvm.vector.reduce.and.v32i8(<32 x i8>)
declare i8 @llvm.vector.reduce.and.v64i8(<64 x i8>)
declare i8 @llvm.vector.reduce.and.v128i8(<128 x i8>)
;; NOTE: These prefixes are unused and the list is autogenerated. Do not add tests below this line:
; AVX1OR2: {{.*}}
; AVX512BW: {{.*}}
; AVX512BWVL: {{.*}}
; AVX512F: {{.*}}
