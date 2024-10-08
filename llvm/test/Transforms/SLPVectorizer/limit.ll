; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: %if x86-registered-target %{ opt < %s -passes=slp-vectorizer -S -mtriple=x86_64-unknown-linux-gnu | FileCheck %s %}
; RUN: %if aarch64-registered-target %{ opt < %s -passes=slp-vectorizer -S -mtriple=aarch64-unknown-linux-gnu | FileCheck %s %}

@b = common global [4 x i32] zeroinitializer, align 16
@c = common global [4 x i32] zeroinitializer, align 16
@d = common global [4 x i32] zeroinitializer, align 16
@e = common global [4 x i32] zeroinitializer, align 16
@a = common global [4 x i32] zeroinitializer, align 16
@fb = common global [4 x float] zeroinitializer, align 16
@fc = common global [4 x float] zeroinitializer, align 16
@fa = common global [4 x float] zeroinitializer, align 16
@fd = common global [4 x float] zeroinitializer, align 16

define void @addsub() {
; CHECK-LABEL: @addsub(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[BB1:%.*]]
; CHECK:       bb1:
; CHECK-NEXT:    [[TMP0:%.*]] = load <4 x i32>, ptr @b, align 16
; CHECK-NEXT:    [[TMP1:%.*]] = load <4 x i32>, ptr @c, align 16
; CHECK-NEXT:    [[TMP2:%.*]] = add nsw <4 x i32> [[TMP0]], [[TMP1]]
; CHECK-NEXT:    [[TMP3:%.*]] = load <4 x i32>, ptr @d, align 16
; CHECK-NEXT:    [[TMP4:%.*]] = load <4 x i32>, ptr @e, align 16
; CHECK-NEXT:    [[TMP5:%.*]] = add nsw <4 x i32> [[TMP3]], [[TMP4]]
; CHECK-NEXT:    [[TMP6:%.*]] = add nsw <4 x i32> [[TMP2]], [[TMP5]]
; CHECK-NEXT:    [[TMP7:%.*]] = sub nsw <4 x i32> [[TMP2]], [[TMP5]]
; CHECK-NEXT:    [[TMP8:%.*]] = shufflevector <4 x i32> [[TMP6]], <4 x i32> [[TMP7]], <4 x i32> <i32 0, i32 5, i32 2, i32 7>
; CHECK-NEXT:    store <4 x i32> [[TMP8]], ptr @a, align 16
; CHECK-NEXT:    ret void
;
entry:
  br label %bb1

bb1:
  %0 = load i32, ptr @b, align 16
  %1 = load i32, ptr @c, align 16
  %add = add nsw i32 %0, %1
  %2 = load i32, ptr @d, align 16
  %3 = load i32, ptr @e, align 16
  %add1 = add nsw i32 %2, %3
  %add2 = add nsw i32 %add, %add1
  store i32 %add2, ptr @a, align 16
  %4 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @b, i64 0, i64 1), align 4
  %5 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @c, i64 0, i64 1), align 4
  %add3 = add nsw i32 %4, %5
  %6 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @d, i64 0, i64 1), align 4
  %7 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @e, i64 0, i64 1), align 4
  %add4 = add nsw i32 %6, %7
  %sub = sub nsw i32 %add3, %add4
  store i32 %sub, ptr getelementptr inbounds ([4 x i32], ptr @a, i64 0, i64 1), align 4
  %8 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @b, i64 0, i64 2), align 8
  %9 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @c, i64 0, i64 2), align 8
  %add5 = add nsw i32 %8, %9
  %10 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @d, i64 0, i64 2), align 8
  %11 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @e, i64 0, i64 2), align 8
  %add6 = add nsw i32 %10, %11
  %add7 = add nsw i32 %add5, %add6
  store i32 %add7, ptr getelementptr inbounds ([4 x i32], ptr @a, i64 0, i64 2), align 8
  %12 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @b, i64 0, i64 3), align 4
  %13 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @c, i64 0, i64 3), align 4
  %add8 = add nsw i32 %12, %13
  %14 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @d, i64 0, i64 3), align 4
  %15 = load i32, ptr getelementptr inbounds ([4 x i32], ptr @e, i64 0, i64 3), align 4
  %add9 = add nsw i32 %14, %15
  %sub10 = sub nsw i32 %add8, %add9
  store i32 %sub10, ptr getelementptr inbounds ([4 x i32], ptr @a, i64 0, i64 3), align 4
  ret void
}
