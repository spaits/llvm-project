add_llvm_library(Attribute MODULE Attribute.cpp PLUGIN_TOOL clang)

if(WIN32 OR CYGWIN)
  set(LLVM_LINK_COMPONENTS
    Support
  )
  clang_target_link_libraries(Attribute PRIVATE
    clangAST
    clangBasic
    clangFrontend
    clangLex
    )
endif()
