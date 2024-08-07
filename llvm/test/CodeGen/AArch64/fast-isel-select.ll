; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py UTC_ARGS: --version 5
; RUN: llc -mtriple=aarch64-apple-darwin                             -verify-machineinstrs < %s | FileCheck %s --check-prefixes=CHECK,CHECK-SDAGISEL
; RUN: llc -mtriple=aarch64-apple-darwin -fast-isel -fast-isel-abort=1 -verify-machineinstrs < %s | FileCheck %s --check-prefixes=CHECK,CHECK-FASTISEL
; RUN: llc -mtriple=aarch64-apple-darwin -global-isel -verify-machineinstrs < %s | FileCheck %s --check-prefixes=CHECK,CHECK-GISEL

; First test the different supported value types for select.
define zeroext i1 @select_i1(i1 zeroext %c, i1 zeroext %a, i1 zeroext %b) {
; CHECK-SDAGISEL-LABEL: select_i1:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    cmp w0, #0
; CHECK-SDAGISEL-NEXT:    csel w0, w1, w2, ne
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_i1:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    tst w0, #0x1
; CHECK-FASTISEL-NEXT:    csel w8, w1, w2, ne
; CHECK-FASTISEL-NEXT:    and w0, w8, #0x1
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_i1:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    tst w0, #0x1
; CHECK-GISEL-NEXT:    csel w0, w1, w2, ne
; CHECK-GISEL-NEXT:    ret
  %1 = select i1 %c, i1 %a, i1 %b
  ret i1 %1
}

define zeroext i8 @select_i8(i1 zeroext %c, i8 zeroext %a, i8 zeroext %b) {
; CHECK-SDAGISEL-LABEL: select_i8:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    cmp w0, #0
; CHECK-SDAGISEL-NEXT:    csel w0, w1, w2, ne
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_i8:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    tst w0, #0x1
; CHECK-FASTISEL-NEXT:    csel w8, w1, w2, ne
; CHECK-FASTISEL-NEXT:    uxtb w0, w8
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_i8:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    tst w0, #0x1
; CHECK-GISEL-NEXT:    csel w0, w1, w2, ne
; CHECK-GISEL-NEXT:    ret
  %1 = select i1 %c, i8 %a, i8 %b
  ret i8 %1
}

define zeroext i16 @select_i16(i1 zeroext %c, i16 zeroext %a, i16 zeroext %b) {
; CHECK-SDAGISEL-LABEL: select_i16:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    cmp w0, #0
; CHECK-SDAGISEL-NEXT:    csel w0, w1, w2, ne
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_i16:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    tst w0, #0x1
; CHECK-FASTISEL-NEXT:    csel w8, w1, w2, ne
; CHECK-FASTISEL-NEXT:    uxth w0, w8
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_i16:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    tst w0, #0x1
; CHECK-GISEL-NEXT:    csel w0, w1, w2, ne
; CHECK-GISEL-NEXT:    ret
  %1 = select i1 %c, i16 %a, i16 %b
  ret i16 %1
}

define i32 @select_i32(i1 zeroext %c, i32 %a, i32 %b) {
; CHECK-SDAGISEL-LABEL: select_i32:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    cmp w0, #0
; CHECK-SDAGISEL-NEXT:    csel w0, w1, w2, ne
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_i32:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    tst w0, #0x1
; CHECK-FASTISEL-NEXT:    csel w0, w1, w2, ne
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_i32:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    tst w0, #0x1
; CHECK-GISEL-NEXT:    csel w0, w1, w2, ne
; CHECK-GISEL-NEXT:    ret
  %1 = select i1 %c, i32 %a, i32 %b
  ret i32 %1
}

define i64 @select_i64(i1 zeroext %c, i64 %a, i64 %b) {
; CHECK-SDAGISEL-LABEL: select_i64:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    cmp w0, #0
; CHECK-SDAGISEL-NEXT:    csel x0, x1, x2, ne
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_i64:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    tst w0, #0x1
; CHECK-FASTISEL-NEXT:    csel x0, x1, x2, ne
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_i64:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    tst w0, #0x1
; CHECK-GISEL-NEXT:    csel x0, x1, x2, ne
; CHECK-GISEL-NEXT:    ret
  %1 = select i1 %c, i64 %a, i64 %b
  ret i64 %1
}

define float @select_f32(i1 zeroext %c, float %a, float %b) {
; CHECK-SDAGISEL-LABEL: select_f32:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    cmp w0, #0
; CHECK-SDAGISEL-NEXT:    fcsel s0, s0, s1, ne
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_f32:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    tst w0, #0x1
; CHECK-FASTISEL-NEXT:    fcsel s0, s0, s1, ne
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_f32:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    tst w0, #0x1
; CHECK-GISEL-NEXT:    fcsel s0, s0, s1, ne
; CHECK-GISEL-NEXT:    ret
  %1 = select i1 %c, float %a, float %b
  ret float %1
}

define double @select_f64(i1 zeroext %c, double %a, double %b) {
; CHECK-SDAGISEL-LABEL: select_f64:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    cmp w0, #0
; CHECK-SDAGISEL-NEXT:    fcsel d0, d0, d1, ne
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_f64:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    tst w0, #0x1
; CHECK-FASTISEL-NEXT:    fcsel d0, d0, d1, ne
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_f64:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    tst w0, #0x1
; CHECK-GISEL-NEXT:    fcsel d0, d0, d1, ne
; CHECK-GISEL-NEXT:    ret
  %1 = select i1 %c, double %a, double %b
  ret double %1
}

; Now test the folding of all compares.
define float @select_fcmp_false(float %x, float %a, float %b) {
; CHECK-SDAGISEL-LABEL: select_fcmp_false:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    fmov s0, s2
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_fcmp_false:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    fmov s0, s2
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_fcmp_false:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    fcmp s0, s0
; CHECK-GISEL-NEXT:    fcsel s0, s1, s2, gt
; CHECK-GISEL-NEXT:    ret
  %1 = fcmp ogt float %x, %x
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_ogt(float %x, float %y, float %a, float %b) {
; CHECK-LABEL: select_fcmp_ogt:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    fcmp s0, s1
; CHECK-NEXT:    fcsel s0, s2, s3, gt
; CHECK-NEXT:    ret
  %1 = fcmp ogt float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_oge(float %x, float %y, float %a, float %b) {
; CHECK-LABEL: select_fcmp_oge:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    fcmp s0, s1
; CHECK-NEXT:    fcsel s0, s2, s3, ge
; CHECK-NEXT:    ret
  %1 = fcmp oge float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_olt(float %x, float %y, float %a, float %b) {
; CHECK-LABEL: select_fcmp_olt:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    fcmp s0, s1
; CHECK-NEXT:    fcsel s0, s2, s3, mi
; CHECK-NEXT:    ret
  %1 = fcmp olt float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_ole(float %x, float %y, float %a, float %b) {
; CHECK-LABEL: select_fcmp_ole:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    fcmp s0, s1
; CHECK-NEXT:    fcsel s0, s2, s3, ls
; CHECK-NEXT:    ret
  %1 = fcmp ole float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_one(float %x, float %y, float %a, float %b) {
; CHECK-SDAGISEL-LABEL: select_fcmp_one:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    fcmp s0, s1
; CHECK-SDAGISEL-NEXT:    fcsel s0, s2, s3, mi
; CHECK-SDAGISEL-NEXT:    fcsel s0, s2, s0, gt
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_fcmp_one:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    fcmp s0, s1
; CHECK-FASTISEL-NEXT:    fcsel s0, s2, s3, mi
; CHECK-FASTISEL-NEXT:    fcsel s0, s2, s0, gt
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_fcmp_one:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    fcmp s0, s1
; CHECK-GISEL-NEXT:    cset w8, mi
; CHECK-GISEL-NEXT:    cset w9, gt
; CHECK-GISEL-NEXT:    orr w8, w8, w9
; CHECK-GISEL-NEXT:    tst w8, #0x1
; CHECK-GISEL-NEXT:    fcsel s0, s2, s3, ne
; CHECK-GISEL-NEXT:    ret
  %1 = fcmp one float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_ord(float %x, float %y, float %a, float %b) {
; CHECK-LABEL: select_fcmp_ord:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    fcmp s0, s1
; CHECK-NEXT:    fcsel s0, s2, s3, vc
; CHECK-NEXT:    ret
  %1 = fcmp ord float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_uno(float %x, float %y, float %a, float %b) {
; CHECK-LABEL: select_fcmp_uno:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    fcmp s0, s1
; CHECK-NEXT:    fcsel s0, s2, s3, vs
; CHECK-NEXT:    ret
  %1 = fcmp uno float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_ueq(float %x, float %y, float %a, float %b) {
; CHECK-SDAGISEL-LABEL: select_fcmp_ueq:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    fcmp s0, s1
; CHECK-SDAGISEL-NEXT:    fcsel s0, s2, s3, eq
; CHECK-SDAGISEL-NEXT:    fcsel s0, s2, s0, vs
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_fcmp_ueq:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    fcmp s0, s1
; CHECK-FASTISEL-NEXT:    fcsel s0, s2, s3, eq
; CHECK-FASTISEL-NEXT:    fcsel s0, s2, s0, vs
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_fcmp_ueq:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    fcmp s0, s1
; CHECK-GISEL-NEXT:    cset w8, eq
; CHECK-GISEL-NEXT:    cset w9, vs
; CHECK-GISEL-NEXT:    orr w8, w8, w9
; CHECK-GISEL-NEXT:    tst w8, #0x1
; CHECK-GISEL-NEXT:    fcsel s0, s2, s3, ne
; CHECK-GISEL-NEXT:    ret
  %1 = fcmp ueq float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_ugt(float %x, float %y, float %a, float %b) {
; CHECK-LABEL: select_fcmp_ugt:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    fcmp s0, s1
; CHECK-NEXT:    fcsel s0, s2, s3, hi
; CHECK-NEXT:    ret
  %1 = fcmp ugt float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_uge(float %x, float %y, float %a, float %b) {
; CHECK-LABEL: select_fcmp_uge:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    fcmp s0, s1
; CHECK-NEXT:    fcsel s0, s2, s3, pl
; CHECK-NEXT:    ret
  %1 = fcmp uge float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_ult(float %x, float %y, float %a, float %b) {
; CHECK-LABEL: select_fcmp_ult:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    fcmp s0, s1
; CHECK-NEXT:    fcsel s0, s2, s3, lt
; CHECK-NEXT:    ret
  %1 = fcmp ult float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}


define float @select_fcmp_ule(float %x, float %y, float %a, float %b) {
; CHECK-LABEL: select_fcmp_ule:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    fcmp s0, s1
; CHECK-NEXT:    fcsel s0, s2, s3, le
; CHECK-NEXT:    ret
  %1 = fcmp ule float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_une(float %x, float %y, float %a, float %b) {
; CHECK-LABEL: select_fcmp_une:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    fcmp s0, s1
; CHECK-NEXT:    fcsel s0, s2, s3, ne
; CHECK-NEXT:    ret
  %1 = fcmp une float %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_fcmp_true(float %x, float %a, float %b) {
; CHECK-SDAGISEL-LABEL: select_fcmp_true:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    fmov s0, s1
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_fcmp_true:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    fmov s0, s1
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_fcmp_true:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    fcmp s0, s0
; CHECK-GISEL-NEXT:    cset w8, eq
; CHECK-GISEL-NEXT:    cset w9, vs
; CHECK-GISEL-NEXT:    orr w8, w8, w9
; CHECK-GISEL-NEXT:    tst w8, #0x1
; CHECK-GISEL-NEXT:    fcsel s0, s1, s2, ne
; CHECK-GISEL-NEXT:    ret
  %1 = fcmp ueq float %x, %x
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_icmp_eq(i32 %x, i32 %y, float %a, float %b) {
; CHECK-LABEL: select_icmp_eq:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    cmp w0, w1
; CHECK-NEXT:    fcsel s0, s0, s1, eq
; CHECK-NEXT:    ret
  %1 = icmp eq i32 %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_icmp_ne(i32 %x, i32 %y, float %a, float %b) {
; CHECK-LABEL: select_icmp_ne:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    cmp w0, w1
; CHECK-NEXT:    fcsel s0, s0, s1, ne
; CHECK-NEXT:    ret
  %1 = icmp ne i32 %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_icmp_ugt(i32 %x, i32 %y, float %a, float %b) {
; CHECK-LABEL: select_icmp_ugt:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    cmp w0, w1
; CHECK-NEXT:    fcsel s0, s0, s1, hi
; CHECK-NEXT:    ret
  %1 = icmp ugt i32 %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_icmp_uge(i32 %x, i32 %y, float %a, float %b) {
; CHECK-LABEL: select_icmp_uge:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    cmp w0, w1
; CHECK-NEXT:    fcsel s0, s0, s1, hs
; CHECK-NEXT:    ret
  %1 = icmp uge i32 %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_icmp_ult(i32 %x, i32 %y, float %a, float %b) {
; CHECK-LABEL: select_icmp_ult:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    cmp w0, w1
; CHECK-NEXT:    fcsel s0, s0, s1, lo
; CHECK-NEXT:    ret
  %1 = icmp ult i32 %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_icmp_ule(i32 %x, i32 %y, float %a, float %b) {
; CHECK-LABEL: select_icmp_ule:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    cmp w0, w1
; CHECK-NEXT:    fcsel s0, s0, s1, ls
; CHECK-NEXT:    ret
  %1 = icmp ule i32 %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_icmp_sgt(i32 %x, i32 %y, float %a, float %b) {
; CHECK-LABEL: select_icmp_sgt:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    cmp w0, w1
; CHECK-NEXT:    fcsel s0, s0, s1, gt
; CHECK-NEXT:    ret
  %1 = icmp sgt i32 %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_icmp_sge(i32 %x, i32 %y, float %a, float %b) {
; CHECK-LABEL: select_icmp_sge:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    cmp w0, w1
; CHECK-NEXT:    fcsel s0, s0, s1, ge
; CHECK-NEXT:    ret
  %1 = icmp sge i32 %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_icmp_slt(i32 %x, i32 %y, float %a, float %b) {
; CHECK-LABEL: select_icmp_slt:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    cmp w0, w1
; CHECK-NEXT:    fcsel s0, s0, s1, lt
; CHECK-NEXT:    ret
  %1 = icmp slt i32 %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

define float @select_icmp_sle(i32 %x, i32 %y, float %a, float %b) {
; CHECK-LABEL: select_icmp_sle:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    cmp w0, w1
; CHECK-NEXT:    fcsel s0, s0, s1, le
; CHECK-NEXT:    ret
  %1 = icmp sle i32 %x, %y
  %2 = select i1 %1, float %a, float %b
  ret float %2
}

; Test peephole optimizations for select.
define zeroext i1 @select_opt1(i1 zeroext %c, i1 zeroext %a) {
; CHECK-LABEL: select_opt1:
; CHECK:       ; %bb.0:
; CHECK-NEXT:    orr w8, w0, w1
; CHECK-NEXT:    and w0, w8, #0x1
; CHECK-NEXT:    ret
  %1 = select i1 %c, i1 true, i1 %a
  ret i1 %1
}

define zeroext i1 @select_opt2(i1 zeroext %c, i1 zeroext %a) {
; CHECK-SDAGISEL-LABEL: select_opt2:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    orn w8, w1, w0
; CHECK-SDAGISEL-NEXT:    and w0, w8, #0x1
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_opt2:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    eor w8, w0, #0x1
; CHECK-FASTISEL-NEXT:    orr w8, w8, w1
; CHECK-FASTISEL-NEXT:    and w0, w8, #0x1
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_opt2:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    eor w8, w0, #0x1
; CHECK-GISEL-NEXT:    orr w8, w8, w1
; CHECK-GISEL-NEXT:    and w0, w8, #0x1
; CHECK-GISEL-NEXT:    ret
  %1 = select i1 %c, i1 %a, i1 true
  ret i1 %1
}

define zeroext i1 @select_opt3(i1 zeroext %c, i1 zeroext %a) {
; CHECK-SDAGISEL-LABEL: select_opt3:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    eor w8, w0, #0x1
; CHECK-SDAGISEL-NEXT:    and w0, w8, w1
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_opt3:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    bic w8, w1, w0
; CHECK-FASTISEL-NEXT:    and w0, w8, #0x1
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_opt3:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    eor w8, w0, #0x1
; CHECK-GISEL-NEXT:    and w0, w8, w1
; CHECK-GISEL-NEXT:    ret
  %1 = select i1 %c, i1 false, i1 %a
  ret i1 %1
}

define zeroext i1 @select_opt4(i1 zeroext %c, i1 zeroext %a) {
; CHECK-SDAGISEL-LABEL: select_opt4:
; CHECK-SDAGISEL:       ; %bb.0:
; CHECK-SDAGISEL-NEXT:    and w0, w0, w1
; CHECK-SDAGISEL-NEXT:    ret
;
; CHECK-FASTISEL-LABEL: select_opt4:
; CHECK-FASTISEL:       ; %bb.0:
; CHECK-FASTISEL-NEXT:    and w8, w0, w1
; CHECK-FASTISEL-NEXT:    and w0, w8, #0x1
; CHECK-FASTISEL-NEXT:    ret
;
; CHECK-GISEL-LABEL: select_opt4:
; CHECK-GISEL:       ; %bb.0:
; CHECK-GISEL-NEXT:    and w0, w0, w1
; CHECK-GISEL-NEXT:    ret
  %1 = select i1 %c, i1 %a, i1 false
  ret i1 %1
}
