add_executable(test_corosh test_corosh.cpp)
target_link_libraries(test_corosh PRIVATE corosh)
add_test(NAME test_corosh COMMAND test_corosh)
