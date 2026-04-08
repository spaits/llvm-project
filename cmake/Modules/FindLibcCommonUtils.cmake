#===--------------------------------------------------------------------===//
#
# Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
# See https://llvm.org/LICENSE.txt for details.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
#===--------------------------------------------------------------------===//

set(libc_path ${CMAKE_CURRENT_LIST_DIR}/../../libc)

function(use_libc_common_utils target)
  if (NOT EXISTS ${libc_path} OR NOT IS_DIRECTORY ${libc_path})
    return()
  endif()

  get_target_property(_libc_common_utils_target_type ${target} TYPE)
  if (_libc_common_utils_target_type STREQUAL "INTERFACE_LIBRARY")
    set(_libc_common_utils_scope INTERFACE)
  else()
    set(_libc_common_utils_scope PRIVATE)
  endif()

  # TODO: Reorganize the libc shared section so that it can be included without
  # adding the root "libc" directory to the include path.
  target_include_directories(${target} ${_libc_common_utils_scope} ${libc_path})
  target_compile_definitions(${target} ${_libc_common_utils_scope} LIBC_NAMESPACE=__llvm_libc_common_utils)
  if (NOT(LIBCXX_ENABLE_THREADS))
    target_compile_definitions(${target} ${_libc_common_utils_scope} LIBC_THREAD_MODE=LIBC_THREAD_MODE_SINGLE)
  endif()
endfunction()

if(NOT TARGET llvm-libc-common-utilities)
  if (EXISTS ${libc_path} AND IS_DIRECTORY ${libc_path})
    add_library(llvm-libc-common-utilities INTERFACE)
    target_compile_features(llvm-libc-common-utilities INTERFACE cxx_std_17)
    use_libc_common_utils(llvm-libc-common-utilities)
  endif()
endif()
