/**
 * test_mock_client.c
 * 
 * Unit tests for mock client init, opening, closing, and destroying.
 * 
 * Test file dependencies:
 *  - test_endpoints.c
 */

#include <stdbool.h>
#include <stddef.h>

#include "esp_heap_caps.h"
#include "unity.h"
#include "sdkconfig.h"

#include "mock_esp_http_client.h"
#include "wrap_esp_http_client_internal.h"

#ifndef CONFIG_TEST_ESP_HTTP_CLIENT_WRAPPER
#error "esp_http_client_wrapper testing without CONFIG_TEST_ESP_HTTP_CLIENT_WRAPPER set!"
#endif /* CONFIG_TEST_ESP_HTTP_CLIENT_WRAPPER */

#ifndef CONFIG_HEAP_USE_HOOKS
#error "esp_http_client_wrapper testing without CONFIG_HEAP_USE_HOOKS set!"
#endif /*CONFIG_HEAP_USE_HOOKS */

#if CONFIG_MAX_NUM_CLIENT_ENDPOINTS != 2
#error "esp_http_client_wrapper tests require CONFIG_MAX_NUM_ENDPOINTS == 2!"
#endif /* CONFIG_MAX_NUM_ENDPOINTS != 2 */

/** A positive value indicates more malloc than free, negative is opposite. */
static int mallocCntr = 0;

/** A tally of the number of times the fail callback has been called */
static int failCallbackCntr = 0;

void esp_heap_trace_alloc_hook(void* ptr, size_t size, uint32_t caps)
{
    mallocCntr++;
}

void esp_heap_trace_free_hook(void* ptr)
{
    mallocCntr--;
}

void fail_callback(void)
{
    failCallbackCntr++;
}

TEST_CASE("client_initAndCleanup", "[wrap_http_client]")
{
    esp_err_t err;
    esp_http_client_handle_t mockClient;
    const esp_http_client_config_t config = {
        .url = "https://bearanvil.com",
    };

    mallocCntr = 0;
    mockClient = wrap_esp_http_client_init(&config);
    TEST_ASSERT_NOT_EQUAL(NULL, mockClient);
    TEST_ASSERT_EQUAL(2, mallocCntr);

    err = wrap_esp_http_client_cleanup(mockClient);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    TEST_ASSERT_EQUAL(0, mallocCntr);
}

TEST_CASE("client_integration1", "[wrap_http_client]")
{
    const char *response = "Hello, World!";
    char buffer[128];
    esp_err_t err;
    int bytesRead;
    esp_http_client_handle_t mockClient;
    const esp_http_client_config_t config = {
        .url = "https://bearanvil.com"
    };

    const MockHttpEndpoint endpoint = {
        .url = "https://bearanvil.com",
        .contentLen = strlen(response) + 1, // need to include null-terminator
        .response = response,
        .responseCode = 200,
    };

    mock_esp_http_client_setup();

    err = mock_esp_http_client_add_endpoint(endpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    mallocCntr = 0;
    mockClient = wrap_esp_http_client_init(&config);
    TEST_ASSERT_NOT_EQUAL(NULL, mockClient);
    TEST_ASSERT_EQUAL(2, mallocCntr);

    err = wrap_esp_http_client_open(mockClient, 0);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    bytesRead = wrap_esp_http_client_read(mockClient, buffer, 128);
    TEST_ASSERT_EQUAL(strlen(response) + 1, bytesRead);
    TEST_ASSERT_EQUAL_STRING(response, buffer);

    err = wrap_esp_http_client_close(mockClient);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    err = wrap_esp_http_client_cleanup(mockClient);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    TEST_ASSERT_EQUAL(0, mallocCntr);
}

TEST_CASE("client_integration2", "[wrap_http_client]")
{
    const char *response = "Hello, World!";
    char buffer[128];
    esp_err_t err;
    int bytesRead;
    esp_http_client_handle_t mockClient;
    const esp_http_client_config_t config = {
        .url = "https://bearanvil.com"
    };

    const MockHttpEndpoint endpoint = {
        .url = "https://bearanvil.com",
        .contentLen = strlen(response) + 1, // need to include null-terminator
        .response = response,
        .responseCode = 200,
    };

    mock_esp_http_client_setup();

    err = mock_esp_http_client_add_endpoint(endpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    mallocCntr = 0;
    mockClient = wrap_esp_http_client_init(&config);
    TEST_ASSERT_NOT_EQUAL(NULL, mockClient);
    TEST_ASSERT_EQUAL(2, mallocCntr);

    err = wrap_esp_http_client_open(mockClient, 0);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    bytesRead = wrap_esp_http_client_read(mockClient, buffer, 4);
    TEST_ASSERT_EQUAL(4, bytesRead);
    buffer[bytesRead + 1] = '\0';
    TEST_ASSERT_EQUAL_STRING("Hell", buffer);

    bytesRead = wrap_esp_http_client_read(mockClient, buffer, 128);
    TEST_ASSERT_EQUAL(10, bytesRead);
    TEST_ASSERT_EQUAL_STRING("o, World!", buffer);

    err = wrap_esp_http_client_close(mockClient);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    err = wrap_esp_http_client_cleanup(mockClient);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    TEST_ASSERT_EQUAL(0, mallocCntr);
}

TEST_CASE("client_closeTwice", "[wrap_http_client]")
{
    const char *response = "Hello, World!";
    char buffer[128];
    esp_err_t err;
    int bytesRead;
    esp_http_client_handle_t mockClient;
    const esp_http_client_config_t config = {
        .url = "https://bearanvil.com"
    };

    const MockHttpEndpoint endpoint = {
        .url = "https://bearanvil.com",
        .contentLen = strlen(response) + 1, // need to include null-terminator
        .response = response,
        .responseCode = 200,
    };

    mock_esp_http_client_setup();

    err = mock_esp_http_client_add_endpoint(endpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    mallocCntr = 0;
    mockClient = wrap_esp_http_client_init(&config);
    TEST_ASSERT_NOT_EQUAL(NULL, mockClient);
    TEST_ASSERT_EQUAL(2, mallocCntr);

    err = wrap_esp_http_client_open(mockClient, 0);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    bytesRead = wrap_esp_http_client_read(mockClient, buffer, 128);
    TEST_ASSERT_EQUAL(strlen(response) + 1, bytesRead);
    TEST_ASSERT_EQUAL_STRING(response, buffer);

    err = wrap_esp_http_client_close(mockClient);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    err = wrap_esp_http_client_close(mockClient);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, err);

    err = wrap_esp_http_client_cleanup(mockClient);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    TEST_ASSERT_EQUAL(0, mallocCntr);
}

TEST_CASE("client_failCallback", "[wrap_http_client]")
{
    const char *response = "Hello, World!";
    char buffer[128];
    esp_err_t err;
    int bytesRead;
    esp_http_client_handle_t mockClient;
    const esp_http_client_config_t config = {
        .url = "https://bearanvil.com"
    };

    const MockHttpEndpoint endpoint = {
        .url = "https://bearanvil.com",
        .contentLen = strlen(response) + 1, // need to include null-terminator
        .response = response,
        .responseCode = 200,
    };

    mallocCntr = 0;
    failCallbackCntr = 0;
    mock_esp_http_client_setup();

    mock_esp_http_client_register_fail_callback(fail_callback);

    err = mock_esp_http_client_add_endpoint(endpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    mockClient = wrap_esp_http_client_init(&config);
    TEST_ASSERT_NOT_EQUAL(NULL, mockClient);
    TEST_ASSERT_EQUAL(2, mallocCntr);

    err = wrap_esp_http_client_open(mockClient, 0);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    bytesRead = wrap_esp_http_client_read(mockClient, buffer, 128);
    TEST_ASSERT_EQUAL(strlen(response) + 1, bytesRead);
    TEST_ASSERT_EQUAL_STRING(response, buffer);

    err = wrap_esp_http_client_close(mockClient);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    err = wrap_esp_http_client_close(mockClient);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, err);
    TEST_ASSERT_EQUAL(1, failCallbackCntr);

    err = wrap_esp_http_client_cleanup(mockClient);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    TEST_ASSERT_EQUAL(0, mallocCntr);
}

TEST_CASE("client_noleftovers", "[wrap_http_client]")
{
    const char example_file_start[] asm("_binary_example_file_txt_start");
    const char example_file_end[] asm("_binary_example_file_txt_end");

    const esp_http_client_config_t config = {
        .url = "https://bearanvil.com"
    };

    const MockHttpEndpoint endpoint = {
        .url = "https://bearanvil.com"
        .contentLen = strlen(response) + 1, // need to include null-terminator
    }
}
