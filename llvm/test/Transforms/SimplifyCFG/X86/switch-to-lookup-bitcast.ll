; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --scrub-attributes
; RUN: opt -passes=simplifycfg --switch-to-lookup -S < %s | FileCheck %s
target triple = "x86_64-unknown-linux-gnu"

@alloc0 = private unnamed_addr constant <{ [1 x i8] }> <{ [1 x i8] c"A" }>, align 1
@alloc1 = private unnamed_addr constant <{ [1 x i8] }> <{ [1 x i8] c"B" }>, align 1
@alloc2 = private unnamed_addr constant <{ [1 x i8] }> <{ [1 x i8] c"C" }>, align 1

define { ptr, i64 } @switch_to_lookup_bitcast(i8 %0) unnamed_addr {
; CHECK-LABEL: @switch_to_lookup_bitcast(
; CHECK-NEXT:  start:
; CHECK-NEXT:    [[TMP3:%.*]] = zext i8 [[TMP0:%.*]] to i64
; CHECK-NEXT:    [[SWITCH_GEP:%.*]] = getelementptr inbounds [3 x ptr], ptr @switch.table.switch_to_lookup_bitcast, i64 0, i64 [[TMP3]]
; CHECK-NEXT:    [[SWITCH_LOAD:%.*]] = load ptr, ptr [[SWITCH_GEP]], align 8
; CHECK-NEXT:    [[TMP1:%.*]] = insertvalue { ptr, i64 } undef, ptr [[SWITCH_LOAD]], 0
; CHECK-NEXT:    [[TMP2:%.*]] = insertvalue { ptr, i64 } [[TMP1]], i64 1, 1
; CHECK-NEXT:    ret { ptr, i64 } [[TMP2]]
;
start:
  switch i8 %0, label %default [
  i8 0, label %bb0
  i8 1, label %bb1
  i8 2, label %bb2
  ]

bb0:
  br label %end

bb1:
  br label %end

bb2:
  br label %end

default:
  unreachable

end:
  %.sroa.0.0 = phi ptr [ @alloc0, %bb0 ], [ @alloc1, %bb1 ], [ @alloc2, %bb2 ]
  %1 = insertvalue { ptr, i64 } undef, ptr %.sroa.0.0, 0
  %2 = insertvalue { ptr, i64 } %1, i64 1, 1
  ret { ptr, i64 } %2
}
