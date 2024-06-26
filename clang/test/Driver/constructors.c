// Test whether or not the driver instructs the backend to use .init_array
// sections for global constructors.
//
// CHECK-INIT-ARRAY-NOT: -fno-use-init-array
// CHECK-NO-INIT-ARRAY: -fno-use-init-array
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     --target=i386-unknown-linux \
// RUN:     --sysroot=%S/Inputs/resource_dir \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     --target=i386-unknown-linux \
// RUN:     --sysroot=%S/Inputs/fake_install_tree \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     -fno-use-init-array \
// RUN:     --target=i386-unknown-linux \
// RUN:     --sysroot=%S/Inputs/fake_install_tree \
// RUN:   | FileCheck --check-prefix=CHECK-NO-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     -fno-use-init-array -fuse-init-array \
// RUN:     --target=i386-unknown-linux \
// RUN:     --sysroot=%S/Inputs/fake_install_tree \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     --target=i386-unknown-linux \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     -fuse-init-array \
// RUN:     --target=i386-unknown-linux \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     --target=arm-unknown-linux-androideabi \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     --target=i386-unknown-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     --target=aarch64-none-linux-gnu \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     --target=aarch64-none-elf \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s

// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     --target=arm64-none-linux-gnu \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     --target=arm64-none-none-eabi \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s

// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     --target=i386-unknown-freebsd \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1       \
// RUN:     --target=i386-unknown-freebsd12 \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1        \
// RUN:     --target=sparc-sun-solaris2.11 \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
//
// RUN: %clang -### %s -fsyntax-only 2>&1        \
// RUN:     --target=i386-pc-solaris2.11 \
// RUN:   | FileCheck --check-prefix=CHECK-INIT-ARRAY %s
