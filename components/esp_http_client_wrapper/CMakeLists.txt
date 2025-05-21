
set(srcs "src/wrap_esp_http_client.c")
set(includes "include")

idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS ${includes}
                       REQUIRES esp_http_client
                                cmock)