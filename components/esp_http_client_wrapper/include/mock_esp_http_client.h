/**
 * mock_esp_http_client.h
 * 
 * Contains functions that control the mock behavior
 * of wrapped esp_http_client functions when 
 * CONFIG_MOCK_ESP_HTTP_CLIENT is set. These control
 * functions should be used alongside typical CMock
 * control functions.
 */

#ifndef MOCK_ESP_HTTP_CLIENT_H_5_19_25
#define MOCK_ESP_HTTP_CLIENT_H_5_19_25

#include <stddef.h>
#include "esp_err.h"
#include "esp_http_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief A struct containing information about how the mock esp_http_client
 * component should respond to a given URL.
 */
typedef struct {
    /* A null-terminated c-string of what esp_http_client_set_url should be called with */
    const char *url;
    /* The response code that will be returned by esp_http_client_get_status_code */
    int responseCode;
    /* The response that will be returned in chunks in esp_http_client_read calls.
    May be NULL if a response would be unexpected and contentLen is 0. */
    const char *response;
    /* The size of response, not including the null-terminator */
    int64_t contentLen;
} MockHttpEndpoint;

/**
 * @brief Initializes the mock esp_http_client component. This
 * is required before use of control functions in this file,
 * however is not required to use CMock functions directly.
 * 
 * @note When using control functions in this file, do not
 * stub or add callbacks on CMock esp_http_client mocks because
 * the control functions use stubs in place of CMock for some
 * wrapped functions.
 */
void mock_esp_http_client_setup(void);

void mock_esp_http_client_register_fail_callback(void (*callback)(void));

esp_err_t mock_esp_http_client_add_endpoint(const MockHttpEndpoint endpoint);

esp_err_t mock_esp_http_client_remove_endpoint(const char *url);

esp_err_t mock_esp_http_client_expect_endpoint(esp_http_client_handle_t client, const char *url);

esp_err_t mock_esp_http_client_verify(void);

#ifdef __cplusplus
}
#endif

#endif /* MOCK_ESP_HTTP_CLIENT_H_5_19_25 */
