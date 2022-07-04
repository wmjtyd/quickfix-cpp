if (HAVE_SSL AND WIN32)
set(applink_SOURCE ${OPENSSL_INCLUDE_DIR}/openssl/applink.c)
endif()


link_libraries(libssl.a libcrypto.a libssl.so.1.1)
add_executable(tradeclient-apifiny Application.cpp tradeclient.cpp ${applink_SOURCE})
TARGET_LINK_LIBRARIES(tradeclient-apifiny dl)
#link_directories(${CMAKE_SOURCE_DIR}/examples/tradeclient/lib/openssl/lib/MinGW)
#link_directories(${CMAKE_SOURCE_DIR}/examples/tradeclient/lib/openssl/lib/MinGW)
#target_link_libraries(libcommon.lib openssl.lib libssl.lib libssl_static.lib libcrypto.lib)

#${CMAKE_SOURCE_DIR}/examples/tradeclient/lib/openssl/include

target_include_directories(tradeclient-apifiny PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/include/quickfix ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/examples/tradeclient-apifiny/inc)


target_link_libraries(tradeclient-apifiny ${PROJECT_NAME})

if (NOT WIN32)
ADD_CUSTOM_TARGET(tradeclient-apifiny_target ALL
                  COMMAND ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE:tradeclient> ${CMAKE_SOURCE_DIR}/bin/tradeclient)
else()
set_target_properties(tradeclient-apifiny PROPERTIES
                      RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_SOURCE_DIR}/bin/debug/tradeclient/
                      RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR}/bin/release/tradeclient/
                      RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ${CMAKE_SOURCE_DIR}/bin/release/tradeclient/)
endif()    

