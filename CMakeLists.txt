cmake_minimum_required(VERSION 3.28.0)
project(NETWORKCAP VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++17")


include_directories(include)
link_directories(Lib/x64)


find_package(imgui CONFIG REQUIRED)
find_package(OpenGL REQUIRED)
find_package(glfw3 CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)

file(GLOB_RECURSE SOURCES "src/*.cpp" "src/headers/*.h" "src/headers/*.hpp" "src/imgui_impl/*.h" "src/imgui_impl/*.cpp")

add_executable(NETWORKCAP ${SOURCES})
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

target_link_libraries(NETWORKCAP imgui::imgui OpenGL::GL glfw fmt::fmt Packet.lib wpcap.lib)

