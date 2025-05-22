/**
 * wrap_esp_http_client.h
 * 
 * Contains macros that either resolve to mock esp_http_client functions
 * or actual esp_http_client functions from the esp_http_client component.
 */

#ifndef WRAP_ESP_HTTP_CLIENT_H_5_19_25
#define WRAP_ESP_HTTP_CLIENT_H_5_19_25

#include "esp_http_client.h"
#include "sdkconfig.h"

#include "wrap_esp_http_client_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_MOCK_ESP_HTTP_CLIENT

#define ESP_HTTP_CLIENT_INIT(config) esp_http_client_init(config)
#define ESP_HTTP_CLIENT_PERFORM(client) esp_http_client_perform(client)
#define ESP_HTTP_CLIENT_SET_URL(client, url) esp_http_client_set_url(client, url)
#define ESP_HTTP_CLIENT_OPEN(client, write_len) esp_http_client_open(client, write_len)
#define ESP_HTTP_CLIENT_READ(client, buffer, len) esp_http_client_read(client, buffer, len)
#define ESP_HTTP_CLIENT_GET_STATUS_CODE(client) esp_http_client_get_status_code(client)
#define ESP_HTTP_CLIENT_GET_CONTENT_LENGTH(client) esp_http_client_get_content_length(client)
#define ESP_HTTP_CLIENT_CLOSE(client) esp_http_client_close(client)
#define ESP_HTTP_CLIENT_CLEANUP(client) esp_http_client_cleanup(client)
#define ESP_HTTP_CLIENT_FLUSH_RESPONSE(client, len) esp_http_client_flush_response(client, len)

#else

#define ESP_HTTP_CLIENT_INIT(config) wrap_esp_http_client_init(config)
// #define ESP_HTTP_CLIENT_PERFORM(client) wrap_esp_http_client_perform(client)
#define ESP_HTTP_CLIENT_SET_URL(client, url) wrap_esp_http_client_set_url(client, url)
#define ESP_HTTP_CLIENT_OPEN(client, write_len) wrap_esp_http_client_open(client, write_len)
#define ESP_HTTP_CLIENT_READ(client, buffer, len) wrap_esp_http_client_read(client, buffer, len)
#define ESP_HTTP_CLIENT_GET_STATUS_CODE(client) wrap_esp_http_client_get_status_code(client)
#define ESP_HTTP_CLIENT_GET_CONTENT_LENGTH(client) wrap_esp_http_client_get_content_length(client)
#define ESP_HTTP_CLIENT_CLOSE(client) wrap_esp_http_client_close(client)
#define ESP_HTTP_CLIENT_CLEANUP(client) wrap_esp_http_client_cleanup(client)
#define ESP_HTTP_CLIENT_FLUSH_RESPONSE(client, len) wrap_esp_http_client_flush_response(client, len)

#endif /* CONFIG_MOCK_ESP_HTTP_CLIENT */

#ifdef __cplusplus
}
#endif

#endif /* WRAP_ESP_HTTP_CLIENT_H_5_19_25 */