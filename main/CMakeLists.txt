idf_component_register(SRCS "test_app_main.c"
                       INCLUDE_DIRS "."
                       REQUIRES esp_http_client_wrapper
                                unity
                                cmock)