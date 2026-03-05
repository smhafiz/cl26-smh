add_executable(trecdsa_smoke_test smoke_test.cpp)
target_link_libraries(trecdsa_smoke_test PRIVATE trecdsa_core)
add_test(NAME trecdsa_smoke_test COMMAND $<TARGET_FILE:trecdsa_smoke_test>)

add_executable(trecdsa_failure_test failure_test.cpp)
target_link_libraries(trecdsa_failure_test PRIVATE trecdsa_core)
add_test(NAME trecdsa_failure_test COMMAND $<TARGET_FILE:trecdsa_failure_test>)

add_executable(trecdsa_api_test api_test.cpp)
target_link_libraries(trecdsa_api_test PRIVATE trecdsa_core)
add_test(NAME trecdsa_api_test COMMAND $<TARGET_FILE:trecdsa_api_test>)
