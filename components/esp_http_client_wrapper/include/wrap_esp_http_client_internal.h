/**
 * wrap_esp_http_client_internal.h
 * 
 * Contains definitions of wrap_esp_http_client.c functions for
 * referencing in wrap_esp_http_client.h macros.
 */

#ifndef WRAP_ESP_HTTP_CLIENT_INTERNAL_H_5_19_25
#define WRAP_ESP_HTTP_CLIENT_INTERNAL_H_5_19_25

#include "esp_http_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Functions that are perpetually mocked by CMock.
 */

esp_http_client_handle_t wrap_esp_http_client_init(const esp_http_client_config_t *config);
// esp_err_t wrap_esp_http_client_perform(esp_http_client_handle_t client);
// esp_err_t wrap_esp_http_client_cancel_request(esp_http_client_handle_t client);
esp_err_t wrap_esp_http_client_set_url(esp_http_client_handle_t client, const char *url);
// esp_err_t wrap_sp_http_client_set_post_field(esp_http_client_handle_t client, const char *data, int len);
// int wrap_esp_http_client_get_post_field(esp_http_client_handle_t client, char **data);
// esp_err_t wrap_esp_http_client_set_header(esp_http_client_handle_t client, const char *key, const char *value);
// esp_err_t wrap_esp_http_client_get_header(esp_http_client_handle_t client, const char *key, char **value);
// esp_err_t wrap_esp_http_client_get_username(esp_http_client_handle_t client, char **value);
// esp_err_t wrap_esp_http_client_set_username(esp_http_client_handle_t client, const char *username);
// esp_err_t wrap_esp_http_client_get_password(esp_http_client_handle_t client, char **value);
// esp_err_t wrap_esp_http_client_set_password(esp_http_client_handle_t client, const char *password);
// esp_err_t wrap_esp_http_client_set_authtype(esp_http_client_handle_t client, esp_http_client_auth_type_t auth_type);
// esp_err_t wrap_esp_http_client_get_user_data(esp_http_client_handle_t client, void **data);
// esp_err_t wrap_esp_http_client_set_user_data(esp_http_client_handle_t client, void *data);
// int wrap_esp_http_client_get_errno(esp_http_client_handle_t client);
// esp_err_t wrap_esp_http_client_get_and_clear_last_tls_error(esp_http_client_handle_t client, int *esp_tls_error_code, int *esp_tls_flags);
// esp_err_t wrap_esp_http_client_set_method(esp_http_client_handle_t client, esp_http_client_method_t method);
// esp_err_t wrap_esp_http_client_set_timeout_ms(esp_http_client_handle_t client, int timeout_ms);
// esp_err_t wrap_esp_http_client_delete_header(esp_http_client_handle_t client, const char *key);
// esp_err_t wrap_esp_http_client_delete_all_headers(esp_http_client_handle_t client);
esp_err_t wrap_esp_http_client_open(esp_http_client_handle_t client, int write_len);
// int wrap_esp_http_client_write(esp_http_client_handle_t client, const char *buffer, int len);
// int64_t wrap_esp_http_client_fetch_headers(esp_http_client_handle_t client);
// bool wrap_esp_http_client_is_chunked_response(esp_http_client_handle_t client);
int wrap_esp_http_client_read(esp_http_client_handle_t client, char *buffer, int len);
int wrap_esp_http_client_get_status_code(esp_http_client_handle_t client);
int64_t wrap_esp_http_client_get_content_length(esp_http_client_handle_t client);
esp_err_t wrap_esp_http_client_close(esp_http_client_handle_t client);
esp_err_t wrap_esp_http_client_cleanup(esp_http_client_handle_t client);
// esp_http_client_transport_t wrap_esp_http_client_get_transport_type(esp_http_client_handle_t client);
// esp_err_t wrap_esp_http_client_set_redirection(esp_http_client_handle_t client);
// esp_err_t wrap_esp_http_client_reset_redirect_counter(esp_http_client_handle_t client);
// esp_err_t wrap_esp_http_client_set_auth_data(esp_http_client_handle_t client, const char *auth_data, int len);
// esp_err_t wrap_esp_http_client_add_auth(esp_http_client_handle_t client);
// bool wrap_esp_http_client_is_complete_data_received(esp_http_client_handle_t client);
// int wrap_esp_http_client_read_response(esp_http_client_handle_t client, char *buffer, int len);
esp_err_t wrap_esp_http_client_flush_response(esp_http_client_handle_t client, int *len);
// esp_err_t wrap_esp_http_client_get_url(esp_http_client_handle_t client, char *url, const int len);
// esp_err_t wrap_esp_http_client_get_chunk_length(esp_http_client_handle_t client, int *len);

// esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t *config);
// esp_err_t esp_http_client_perform(esp_http_client_handle_t client);
// esp_err_t esp_http_client_cancel_request(esp_http_client_handle_t client);
// esp_err_t esp_http_client_set_url(esp_http_client_handle_t client, const char *url);
// esp_err_t esp_http_client_set_post_field(esp_http_client_handle_t client, const char *data, int len);
// int esp_http_client_get_post_field(esp_http_client_handle_t client, char **data);
// esp_err_t esp_http_client_set_header(esp_http_client_handle_t client, const char *key, const char *value);
// esp_err_t esp_http_client_get_header(esp_http_client_handle_t client, const char *key, char **value);
// esp_err_t esp_http_client_get_username(esp_http_client_handle_t client, char **value);
// esp_err_t esp_http_client_set_username(esp_http_client_handle_t client, const char *username);
// esp_err_t esp_http_client_get_password(esp_http_client_handle_t client, char **value);
// esp_err_t esp_http_client_set_password(esp_http_client_handle_t client, const char *password);
// esp_err_t esp_http_client_set_authtype(esp_http_client_handle_t client, esp_http_client_auth_type_t auth_type);
// esp_err_t esp_http_client_get_user_data(esp_http_client_handle_t client, void **data);
// esp_err_t esp_http_client_set_user_data(esp_http_client_handle_t client, void *data);
// int esp_http_client_get_errno(esp_http_client_handle_t client);
// esp_err_t esp_http_client_get_and_clear_last_tls_error(esp_http_client_handle_t client, int *esp_tls_error_code, int *esp_tls_flags);
// esp_err_t esp_http_client_set_method(esp_http_client_handle_t client, esp_http_client_method_t method);
// esp_err_t esp_http_client_set_timeout_ms(esp_http_client_handle_t client, int timeout_ms);
// esp_err_t esp_http_client_delete_header(esp_http_client_handle_t client, const char *key);
// esp_err_t esp_http_client_delete_all_headers(esp_http_client_handle_t client);
// esp_err_t esp_http_client_open(esp_http_client_handle_t client, int write_len);
// int esp_http_client_write(esp_http_client_handle_t client, const char *buffer, int len);
// int64_t esp_http_client_fetch_headers(esp_http_client_handle_t client);
// bool esp_http_client_is_chunked_response(esp_http_client_handle_t client);
// int esp_http_client_read(esp_http_client_handle_t client, char *buffer, int len);
// int esp_http_client_get_status_code(esp_http_client_handle_t client);
// int64_t esp_http_client_get_content_length(esp_http_client_handle_t client);
// esp_err_t esp_http_client_close(esp_http_client_handle_t client);
// esp_err_t esp_http_client_cleanup(esp_http_client_handle_t client);
// esp_http_client_transport_t esp_http_client_get_transport_type(esp_http_client_handle_t client);
// esp_err_t esp_http_client_set_redirection(esp_http_client_handle_t client);
// esp_err_t esp_http_client_reset_redirect_counter(esp_http_client_handle_t client);
// esp_err_t esp_http_client_set_auth_data(esp_http_client_handle_t client, const char *auth_data, int len);
// esp_err_t esp_http_client_add_auth(esp_http_client_handle_t client);
// bool esp_http_client_is_complete_data_received(esp_http_client_handle_t client);
// int esp_http_client_read_response(esp_http_client_handle_t client, char *buffer, int len);
// esp_err_t esp_http_client_flush_response(esp_http_client_handle_t client, int *len);
// esp_err_t esp_http_client_get_url(esp_http_client_handle_t client, char *url, const int len);
// esp_err_t esp_http_client_get_chunk_length(esp_http_client_handle_t client, int *len);

#ifdef __cplusplus
}
#endif

#endif /* WRAP_ESP_HTTP_CLIENT_INTERNAL_H_5_19_25 */