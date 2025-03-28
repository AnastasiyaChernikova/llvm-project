//--------------------------------------------------------------------------------------------------
// WHEN CREATING A NEW TEST, PLEASE JUST COPY & PASTE WITHOUT EDITS.
//
// Set-up that's shared across all tests in this directory. In principle, this
// config could be moved to lit.local.cfg. However, there are downstream users that
//  do not use these LIT config files. Hence why this is kept inline.
//
// DEFINE: %{sparsifier_opts} = enable-runtime-library=true
// DEFINE: %{sparsifier_opts_sve} = enable-arm-sve=true %{sparsifier_opts}
// DEFINE: %{compile} = mlir-opt %s --sparsifier="%{sparsifier_opts}"
// DEFINE: %{compile_sve} = mlir-opt %s --sparsifier="%{sparsifier_opts_sve}"
// DEFINE: %{run_libs} = -shared-libs=%mlir_c_runner_utils,%mlir_runner_utils
// DEFINE: %{run_libs_sve} = -shared-libs=%native_mlir_runner_utils,%native_mlir_c_runner_utils
// DEFINE: %{run_opts} = -e main -entry-point-result=void
// DEFINE: %{run} = mlir-runner %{run_opts} %{run_libs}
// DEFINE: %{run_sve} = %mcr_aarch64_cmd --march=aarch64 --mattr="+sve" %{run_opts} %{run_libs_sve}
//
// DEFINE: %{env} =
//--------------------------------------------------------------------------------------------------

// REDEFINE: %{env} = TENSOR0="%mlir_src_dir/test/Integration/data/test.mtx"
// RUN: %{compile} | env %{env} %{run} | FileCheck %s
//
// Do the same run, but now with direct IR generation and vectorization.
// REDEFINE: %{sparsifier_opts} = enable-runtime-library=false vl=2 reassociate-fp-reductions=true enable-index-optimizations=true
// RUN: %{compile} | env %{env} %{run} | FileCheck %s
//
// Do the same run, but now with direct IR generation and, if available, VLA
// vectorization.
// RUN: %if mlir_arm_sve_tests %{ %{compile_sve} | env %{env} %{run_sve} | FileCheck %s %}

!Filename = !llvm.ptr

#DCSR = #sparse_tensor.encoding<{
  map = (d0, d1) -> (d0 : compressed, d1 : compressed)
}>

#eltwise_mult = {
  indexing_maps = [
    affine_map<(i,j) -> (i,j)>  // X (out)
  ],
  iterator_types = ["parallel", "parallel"],
  doc = "X(i,j) *= X(i,j)"
}

//
// Integration test that lowers a kernel annotated as sparse to
// actual sparse code, initializes a matching sparse storage scheme
// from file, and runs the resulting code with the JIT compiler.
//
module {
  //
  // A kernel that multiplies a sparse matrix A with itself
  // in an element-wise fashion. In this operation, we have
  // a sparse tensor as output, but although the values of the
  // sparse tensor change, its nonzero structure remains the same.
  //
  func.func @kernel_eltwise_mult(%argx: tensor<?x?xf64, #DCSR>)
    -> tensor<?x?xf64, #DCSR> {
    %0 = linalg.generic #eltwise_mult
      outs(%argx: tensor<?x?xf64, #DCSR>) {
      ^bb(%x: f64):
        %0 = arith.mulf %x, %x : f64
        linalg.yield %0 : f64
    } -> tensor<?x?xf64, #DCSR>
    return %0 : tensor<?x?xf64, #DCSR>
  }

  func.func private @getTensorFilename(index) -> (!Filename)

  //
  // Main driver that reads matrix from file and calls the sparse kernel.
  //
  func.func @main() {
    %d0 = arith.constant 0.0 : f64
    %c0 = arith.constant 0 : index

    // Read the sparse matrix from file, construct sparse storage.
    %fileName = call @getTensorFilename(%c0) : (index) -> (!Filename)
    %x = sparse_tensor.new %fileName : !Filename to tensor<?x?xf64, #DCSR>

    // Call kernel.
    %0 = call @kernel_eltwise_mult(%x) : (tensor<?x?xf64, #DCSR>) -> tensor<?x?xf64, #DCSR>

    // Print the result for verification.
    //
    // CHECK:      ---- Sparse Tensor ----
    // CHECK-NEXT: nse = 9
    // CHECK-NEXT: dim = ( 5, 5 )
    // CHECK-NEXT: lvl = ( 5, 5 )
    // CHECK-NEXT: pos[0] : ( 0, 5 )
    // CHECK-NEXT: crd[0] : ( 0, 1, 2, 3, 4 )
    // CHECK-NEXT: pos[1] : ( 0, 2, 4, 5, 7, 9 )
    // CHECK-NEXT: crd[1] : ( 0, 3, 1, 4, 2, 0, 3, 1, 4 )
    // CHECK-NEXT: values : ( 1, 1.96, 4, 6.25, 9, 16.81, 16, 27.04, 25 )
    // CHECK-NEXT: ----
    //
    sparse_tensor.print %0 : tensor<?x?xf64, #DCSR>

    // Release the resources.
    bufferization.dealloc_tensor %x : tensor<?x?xf64, #DCSR>

    return
  }
}
