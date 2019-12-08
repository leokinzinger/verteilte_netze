project(Block5 C)

set(CMAKE_C_STANDARD 99)

add_executable(peer server.c )
add_executable(client client.c )