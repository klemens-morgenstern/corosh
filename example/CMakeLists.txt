add_executable(example_client client.cpp)
target_link_libraries(example_client PRIVATE corosh)

add_executable(example_server server.cpp)
target_link_libraries(example_server PRIVATE corosh)
