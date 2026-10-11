cmake_minimum_required(VERSION 3.21)
project(NBA2K26QoLHook VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "This project targets Windows only.")
endif()

# Keep the pure portrait policy introduced on main, and restore the verified
# read-only branch-inspection export required by DllSmokeTest on this branch.
add_library(NBA2K26QoLHook SHARED
  src/main.cpp
  src/PortraitPolicy.cpp
  src/portrait_gate_validation.cpp
)
target_include_directories(NBA2K26QoLHook PRIVATE include)
target_link_libraries(NBA2K26QoLHook PRIVATE bcrypt)
target_compile_features(NBA2K26QoLHook PRIVATE cxx_std_17)
target_compile_definitions(NBA2K26QoLHook PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
set_target_properties(NBA2K26QoLHook PROPERTIES
  OUTPUT_NAME "NBA2K26QoLHook"
  WINDOWS_EXPORT_ALL_SYMBOLS OFF
)

# Test loader initialization with a harmless ASI that never edits game memory.
# Keep it separate from the main DLL.
add_library(NBA2K26PortraitProbe SHARED src/offline_asi_probe.cpp)
target_compile_features(NBA2K26PortraitProbe PRIVATE cxx_std_17)
target_compile_definitions(NBA2K26PortraitProbe PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
set_target_properties(NBA2K26PortraitProbe PROPERTIES
  PREFIX ""
  SUFFIX ".asi"
  OUTPUT_NAME "NBA2K26PortraitProbe"
)


# Standalone read-only process inspector. Does NOT load native plugins into game.
add_executable(NBA2K26PortraitTool src/portrait_tool.cpp)
target_compile_features(NBA2K26PortraitTool PRIVATE cxx_std_17)
target_compile_definitions(NBA2K26PortraitTool PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(NBA2K26PortraitTool PRIVATE bcrypt)

include(CTest)
if(BUILD_TESTING)
  add_test(NAME PortraitToolSelfTest
    COMMAND NBA2K26PortraitTool --self-test)
  add_test(NAME PortraitToolHelp
    COMMAND NBA2K26PortraitTool --help)
  add_executable(DllSmokeTest tests/dll_smoke_test.cpp)
  target_compile_features(DllSmokeTest PRIVATE cxx_std_17)
  add_test(NAME DllSmokeTest
    COMMAND DllSmokeTest "$<TARGET_FILE:NBA2K26QoLHook>")

  add_executable(PortraitPolicyTest tests/portrait_policy_test.cpp src/PortraitPolicy.cpp)
  target_include_directories(PortraitPolicyTest PRIVATE include)
  target_compile_features(PortraitPolicyTest PRIVATE cxx_std_17)
  add_test(NAME PortraitPolicyTest COMMAND PortraitPolicyTest)

  add_executable(PortraitGateValidationTest tests/portrait_gate_validation_test.cpp)
  target_compile_features(PortraitGateValidationTest PRIVATE cxx_std_17)
  add_test(NAME PortraitGateValidationTest COMMAND PortraitGateValidationTest)

  add_executable(AsiProbeSmokeTest tests/asi_probe_smoke_test.cpp)
  target_compile_features(AsiProbeSmokeTest PRIVATE cxx_std_17)
  add_test(NAME AsiProbeSmokeTest
    COMMAND AsiProbeSmokeTest "$<TARGET_FILE:NBA2K26PortraitProbe>")
endif()
