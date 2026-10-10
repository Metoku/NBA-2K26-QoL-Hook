cmake_minimum_required(VERSION 3.21)
project(NBA2K26QoLHook VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "This project targets Windows only.")
endif()

add_library(NBA2K26QoLHook SHARED src/main.cpp src/PortraitPolicy.cpp)
target_include_directories(NBA2K26QoLHook PRIVATE include)
target_compile_features(NBA2K26QoLHook PRIVATE cxx_std_17)
target_compile_definitions(NBA2K26QoLHook PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
set_target_properties(NBA2K26QoLHook PROPERTIES
  OUTPUT_NAME "NBA2K26QoLHook"
  WINDOWS_EXPORT_ALL_SYMBOLS OFF
)

include(CTest)
if(BUILD_TESTING)
  add_executable(DllSmokeTest tests/dll_smoke_test.cpp)
  target_compile_features(DllSmokeTest PRIVATE cxx_std_17)
  add_test(NAME DllSmokeTest
    COMMAND DllSmokeTest "$<TARGET_FILE:NBA2K26QoLHook>")

  add_executable(PortraitPolicyTest tests/portrait_policy_test.cpp src/PortraitPolicy.cpp)
  target_include_directories(PortraitPolicyTest PRIVATE include)
  target_compile_features(PortraitPolicyTest PRIVATE cxx_std_17)
  add_test(NAME PortraitPolicyTest COMMAND PortraitPolicyTest)
endif()
