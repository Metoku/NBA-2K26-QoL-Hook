cmake_minimum_required(VERSION 3.21)
project(NBA2K26QoLHook VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "This project targets Windows only.")
endif()

# A diagnostic ASI plugin that only writes a TEMP confirmation file when loaded.
# No patching or hooks; build and test loader support independently first.
add_library(NBA2K26PortraitProbe SHARED src/offline_asi_probe.cpp)
set_target_properties(NBA2K26PortraitProbe PROPERTIES
  PREFIX ""
  SUFFIX ".asi"
  OUTPUT_NAME "NBA2K26PortraitProbe"
)
target_compile_features(NBA2K26PortraitProbe PRIVATE cxx_std_17)
target_compile_definitions(NBA2K26PortraitProbe PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

add_library(NBA2K26QoLHook SHARED src/main.cpp src/portrait_gate_validation.cpp)
target_link_libraries(NBA2K26QoLHook PRIVATE bcrypt)
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
  add_executable(PortraitGateValidationTest tests/portrait_gate_validation_test.cpp)
  target_compile_features(PortraitGateValidationTest PRIVATE cxx_std_17)
  add_test(NAME PortraitGateValidationTest COMMAND PortraitGateValidationTest)
endif()
