cmake_minimum_required(VERSION 3.21)
project(NBA2K26QoLHook VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "This project targets Windows only.")
endif()

add_library(NBA2K26QoLHook SHARED src/main.cpp)
target_compile_features(NBA2K26QoLHook PRIVATE cxx_std_17)
target_compile_definitions(NBA2K26QoLHook PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
set_target_properties(NBA2K26QoLHook PROPERTIES
  OUTPUT_NAME "NBA2K26QoLHook"
  WINDOWS_EXPORT_ALL_SYMBOLS OFF
)


# Read-only, standalone analysis tool. It does not inject or alter game data.
add_library(PortraitXrefCore STATIC tools/portrait_xref_core.cpp)
target_compile_features(PortraitXrefCore PRIVATE cxx_std_17)
target_include_directories(PortraitXrefCore PUBLIC tools)

add_executable(NBA2K26PortraitXrefProbe WIN32 tools/portrait_xref_probe_win.cpp)
target_compile_features(NBA2K26PortraitXrefProbe PRIVATE cxx_std_17)
target_link_libraries(NBA2K26PortraitXrefProbe PRIVATE PortraitXrefCore comdlg32 user32)
set_target_properties(PortraitXrefCore NBA2K26PortraitXrefProbe PROPERTIES
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

include(CTest)
if(BUILD_TESTING)
  add_executable(PortraitXrefTests tests/portrait_xref_tests.cpp)
  target_compile_features(PortraitXrefTests PRIVATE cxx_std_17)
  target_link_libraries(PortraitXrefTests PRIVATE PortraitXrefCore)
  set_target_properties(PortraitXrefTests PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )
  add_test(NAME PortraitXrefTests COMMAND PortraitXrefTests)
  add_executable(DllSmokeTest tests/dll_smoke_test.cpp)
  target_compile_features(DllSmokeTest PRIVATE cxx_std_17)
  add_test(NAME DllSmokeTest
    COMMAND DllSmokeTest "$<TARGET_FILE:NBA2K26QoLHook>")
endif()
