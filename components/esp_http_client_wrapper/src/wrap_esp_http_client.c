/**
 * wrap_esp_http_client.c
 * 
 * Contains mock control functions that implement mock_esp_http_client.h
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "esp_check.h"
#include "esp_err.h"
#include "esp_http_client.h"
#include "sdkconfig.h"

#include "wrap_esp_http_client_internal.h"
#include "mock_esp_http_client.h"

#ifdef CONFIG_TEST_ESP_HTTP_CLIENT_WRAPPER
#define STATIC_IF_NOT_TEST 
#else
#define STATIC_IF_NOT_TEST static
#endif /* CONFIG_TEST_ESP_HTTP_CLIENT_WRAPPER */

#define TAG "mock_http_client"

#define MOCK_CLIENT_MAGIC 0x49A5

typedef struct {
    bool opened;
    const char *currentURL;
    size_t responseNdx;
    int magic; // to ensure the esp_http_client_handle_t is actually a mock
} mock_http_client;

STATIC_IF_NOT_TEST MockHttpEndpoint endpoints[CONFIG_MAX_NUM_CLIENT_ENDPOINTS];

STATIC_IF_NOT_TEST void (*failCallback)(void) = NULL;

/**
 * @returns endpoint index corresponding to url. If url does
 * not correspond to an endpoint, then CONFIG_MAX_NUM_CLIENT_ENDPOINTS
 * is returned.
 */
static size_t getEndpointNdx(const char *url)
{
    if (url == NULL) return CONFIG_MAX_NUM_CLIENT_ENDPOINTS;
    for (size_t i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        if (endpoints[i].url == NULL) continue;
        if (strcmp(endpoints[i].url, url) == 0) return i;
    }
    return CONFIG_MAX_NUM_CLIENT_ENDPOINTS;
}

/**
 * @brief Initializes the mock esp_http_client component.
 * 
 * @note This clears any existing endpoints and callbacks.
 */
void mock_esp_http_client_setup(void)
{
    for (size_t i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        endpoints[i].url = NULL;
        endpoints[i].response = NULL;
        endpoints[i].contentLen = 0;
        endpoints[i].responseCode = 0;
    }
    failCallback = NULL;
}

/**
 * @brief Registers a callback to run if any mock function fails so that
 * the source of errors can be discovered more easily.
 * 
 * @note If NULL, then no callback will be executed if a mock function fails.
 */
void mock_esp_http_client_register_fail_callback(void (*callback)(void))
{
    failCallback = callback;
}

/**
 * @brief Adds an endpoint that any mock client can retrieve a response from.
 * 
 * @param[in] endpoint The specification of what endpoint should be added. A
 * shallow copy of the struct is made, so the struct itself can be discarded,
 * however pointers within the struct must remain valid while the mock is expected
 * to be interacted with, or until mock_esp_http_client_setup is called again,
 * or until mock_esp_http_client_remove_endpoint is called on this endpoint.
 * 
 * @requires:
 *  - mock esp_http_client component initialized with mock_esp_http_client_setup.
 * 
 * @returns ESP_OK if successful.
 * ESP_ERR_INVALID_ARG if endpoint is malformed.
 * ESP_ERR_NO_MEM if CONFIG_MAX_NUM_CLIENT_ENDPOINTS endpoints were already added.
 */
esp_err_t mock_esp_http_client_add_endpoint(const MockHttpEndpoint endpoint)
{
    /* input guards */
    if (endpoint.url == NULL) return ESP_ERR_INVALID_ARG;
    if (endpoint.response == NULL && endpoint.contentLen != 0) return ESP_ERR_INVALID_ARG;

    /* determine if this endpoint already exists */
    for (size_t i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        MockHttpEndpoint currEndpoint = endpoints[i];
        if (currEndpoint.url == NULL) continue;
        if (strcmp(endpoint.url, currEndpoint.url) == 0) return ESP_ERR_INVALID_ARG;
    }

    /* find first empty endpoint */
    size_t newEndpointNdx = CONFIG_MAX_NUM_CLIENT_ENDPOINTS; // out-of-bounds
    for (size_t i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        if (endpoints[i].url != NULL) continue;
        newEndpointNdx = i;
        break;
    }
    if (newEndpointNdx == CONFIG_MAX_NUM_CLIENT_ENDPOINTS) return (esp_err_t) ESP_ERR_NO_MEM;

    /* add new endpoint to list */
    endpoints[newEndpointNdx] = endpoint;
    return ESP_OK;
}

/**
 * @brief Removes an endpoint previously added by mock_esp_http_client_add_endpoint.
 * 
 * @param[in] url The url of the endpoint to remove.
 * 
 * @returns ESP_OK if successful.
 * ESP_ERR_INVALID_ARG if url is NULL.
 * ESP_ERR_NOT_FOUND if an endpoint with the provided url is not found.
 */
esp_err_t mock_esp_http_client_remove_endpoint(const char *url)
{
    /* input guards */
    if (url == NULL) return (esp_err_t) ESP_ERR_INVALID_ARG;

    /* determine location of the endpoint */
    size_t endpointNdx = CONFIG_MAX_NUM_CLIENT_ENDPOINTS;
    for (size_t i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        if (endpoints[i].url == NULL) continue;
        if (strcmp(endpoints[i].url, url) != 0) continue;
        endpointNdx = i;
    }
    if (endpointNdx == CONFIG_MAX_NUM_CLIENT_ENDPOINTS) return (esp_err_t) ESP_ERR_NOT_FOUND;

    /* clear endpoint */
    endpoints[endpointNdx].url = NULL;
    endpoints[endpointNdx].response = NULL;
    endpoints[endpointNdx].contentLen = 0;
    endpoints[endpointNdx].responseCode = 0;
    return ESP_OK;
}

esp_err_t mock_esp_http_client_expect_endpoint(esp_http_client_handle_t client, const char *url)
{
    return ESP_FAIL;
}

esp_err_t mock_esp_http_client_verify(void)
{
    return ESP_FAIL;
}

/**
 * Stub functions that run in place of typical esp_http_client functions.
 */

esp_http_client_handle_t wrap_esp_http_client_init(const esp_http_client_config_t *config)
{
    esp_http_client_handle_t ret = NULL;
    mock_http_client *mockClient;
    
    /* input guards */
    ESP_GOTO_ON_FALSE(config != NULL && config->url != NULL, 
        NULL, handle_error, TAG, "config != NULL");

    /* allocate and create mock client */
    mockClient = malloc(sizeof(mock_http_client));
    ESP_GOTO_ON_FALSE(mockClient != NULL, 
        NULL, handle_error, TAG, "mockClient != NULL");

    mockClient->currentURL = config->url;
    mockClient->opened = false;
    mockClient->responseNdx = 0;
    mockClient->magic = MOCK_CLIENT_MAGIC;

    return (esp_http_client_handle_t) mockClient;
handle_error:
    if (failCallback != NULL) failCallback();
    return ret;
}

esp_err_t wrap_esp_http_client_set_url(esp_http_client_handle_t client, const char *url)
{
    esp_err_t ret;
    mock_http_client *mockClient;

    /* input guards */
    ESP_GOTO_ON_FALSE(client != NULL && url != NULL, 
        ESP_ERR_INVALID_ARG, handle_error, TAG, "client != NULL && url != NULL");

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    ESP_GOTO_ON_FALSE(mockClient->magic == MOCK_CLIENT_MAGIC, 
        ESP_ERR_INVALID_ARG, handle_error, TAG, "mockClient->magic == MOCK_CLIENT_MAGIC");
    ESP_GOTO_ON_FALSE(!mockClient->opened, 
        ESP_ERR_NOT_SUPPORTED, handle_error, TAG, "!mockClient->opened");

    /* set url */
    mockClient->currentURL = url;
    mockClient->responseNdx = 0;
    return ESP_OK;
handle_error:
    if (failCallback != NULL) failCallback();
    return ret;
}

esp_err_t wrap_esp_http_client_open(esp_http_client_handle_t client, int write_len)
{
    esp_err_t ret;
    mock_http_client *mockClient;
    /* input guards */
    ESP_GOTO_ON_FALSE(client != NULL, 
        ESP_ERR_INVALID_ARG, handle_error, TAG, "client != NULL");
    ESP_GOTO_ON_FALSE(write_len == 0, 
        ESP_ERR_NOT_SUPPORTED, handle_error, TAG, "write_len == 0");

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    ESP_GOTO_ON_FALSE(mockClient->magic == MOCK_CLIENT_MAGIC, 
        ESP_ERR_INVALID_ARG, handle_error, TAG, "mockClient->magic == MOCK_CLIENT_MAGIC");

    /* open mock client */
    ESP_GOTO_ON_FALSE(!mockClient->opened, 
        ESP_ERR_INVALID_STATE, handle_error, TAG, "!mockClient->opened");

    mockClient->opened = true;
    mockClient->responseNdx = 0;
    return ESP_OK;
handle_error:
    if (failCallback != NULL) failCallback();
    return ret;
}

int wrap_esp_http_client_get_status_code(esp_http_client_handle_t client)
{
    esp_err_t ret;
    mock_http_client *mockClient;
    int endpointNdx;

    /* input guards */
    ESP_GOTO_ON_FALSE(client != NULL, 
        ESP_ERR_INVALID_ARG, handle_error, TAG, "client != NULL");

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    ESP_GOTO_ON_FALSE(mockClient->magic == MOCK_CLIENT_MAGIC, 
        ESP_ERR_INVALID_ARG, handle_error, TAG, "mockClient->magic == MOCK_CLIENT_MAGIC");
        
    ESP_GOTO_ON_FALSE(mockClient->currentURL != NULL, 
        ESP_ERR_INVALID_STATE, handle_error, TAG, "mockClient->currentURL != NULL");
    ESP_GOTO_ON_FALSE(mockClient->opened, 
        ESP_ERR_INVALID_STATE, handle_error, TAG, "mockClient->opened");

    /* retrieve status code */
    endpointNdx = getEndpointNdx(mockClient->currentURL);
    ESP_GOTO_ON_FALSE(endpointNdx < CONFIG_MAX_NUM_CLIENT_ENDPOINTS, 
        ESP_ERR_NOT_FOUND, handle_error, TAG, "endpointNdx < CONFIG_MAX_NUM_CLIENT_ENDPOINTS");

    return endpoints[endpointNdx].responseCode;
handle_error:
    if (failCallback != NULL) failCallback();
    return -((int) ret);
}

int64_t wrap_esp_http_client_get_content_length(esp_http_client_handle_t client)
{
    int64_t ret;
    mock_http_client *mockClient;
    int endpointNdx;

    /* input guards */
    ESP_GOTO_ON_FALSE(client != NULL,
        ESP_ERR_INVALID_ARG, handle_error, TAG, "client != NULL");

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    ESP_GOTO_ON_FALSE(mockClient->magic == MOCK_CLIENT_MAGIC,
        ESP_ERR_INVALID_ARG, handle_error, TAG, "mockClient->magic == MOCK_CLIENT_MAGIC");
    ESP_GOTO_ON_FALSE(mockClient->currentURL != NULL,
        ESP_ERR_INVALID_STATE, handle_error, TAG, "mockClient->currentURL != NULL");
    ESP_GOTO_ON_FALSE(mockClient->opened,
        ESP_ERR_INVALID_STATE, handle_error, TAG, "mockClient->opened");

    /* retrieve status code */
    endpointNdx = getEndpointNdx(mockClient->currentURL);
    ESP_GOTO_ON_FALSE(endpointNdx < CONFIG_MAX_NUM_CLIENT_ENDPOINTS,
        ESP_ERR_NOT_FOUND, handle_error, TAG, "endpointNdx < CONFIG_MAX_NUM_CLIENT_ENDPOINTS");

    return endpoints[endpointNdx].contentLen;
handle_error:
    if (failCallback != NULL) failCallback();
    return -ret;
}

int wrap_esp_http_client_read(esp_http_client_handle_t client, char *buffer, int len)
{
    int ret;
    mock_http_client *mockClient;
    MockHttpEndpoint currEndpoint;
    int endpointNdx;
    int readLen;

    /* input guards */
    ESP_GOTO_ON_FALSE(client != NULL,
        ESP_ERR_INVALID_ARG, handle_error, TAG, "client != NULL");
    ESP_GOTO_ON_FALSE(len != 0,
        ESP_ERR_INVALID_ARG, handle_error, TAG, "len != 0");

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    ESP_GOTO_ON_FALSE(mockClient->magic == MOCK_CLIENT_MAGIC,
        ESP_ERR_INVALID_ARG, handle_error, TAG, "mockClient->magic == MOCK_CLIENT_MAGIC");

    ESP_GOTO_ON_FALSE(mockClient->currentURL != NULL,
        ESP_ERR_INVALID_STATE, handle_error, TAG, "mockClient->currentURL != NULL");
    ESP_GOTO_ON_FALSE(mockClient->opened,
        ESP_ERR_INVALID_STATE, handle_error, TAG, "mockClient->opened");

    /* determine endpoint */
    endpointNdx = getEndpointNdx(mockClient->currentURL);
    ESP_GOTO_ON_FALSE(endpointNdx != CONFIG_MAX_NUM_CLIENT_ENDPOINTS,
        ESP_ERR_NOT_FOUND, handle_error, TAG, "endpointNdx != CONFIG_MAX_NUM_CLIENT_ENDPOINTS");
    currEndpoint = endpoints[endpointNdx];

    /* continue reading from response */
    ESP_GOTO_ON_FALSE(mockClient->responseNdx < currEndpoint.contentLen,
        ESP_ERR_INVALID_STATE, handle_error, TAG, "mockClient->responseNdx < currEndpoint.contentLen");
    if (currEndpoint.contentLen - mockClient->responseNdx >= len)
    {
        readLen = len;
    } else
    {
        readLen = currEndpoint.contentLen - mockClient->responseNdx;
    }

    /* update buffer and client */
    memcpy(buffer, &(currEndpoint.response[mockClient->responseNdx]), readLen);
    mockClient->responseNdx += readLen;
    return readLen;
handle_error:
    if (failCallback != NULL) failCallback();
    return -ret;
}

esp_err_t wrap_esp_http_client_close(esp_http_client_handle_t client)
{
    esp_err_t ret;
    mock_http_client *mockClient;

    /* input guards */
    ESP_GOTO_ON_FALSE(client != NULL,
        ESP_ERR_INVALID_ARG, handle_error, TAG, "client != NULL");

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    ESP_GOTO_ON_FALSE(mockClient->magic == MOCK_CLIENT_MAGIC,
        ESP_ERR_INVALID_ARG, handle_error, TAG, "mockClient->magic == MOCK_CLIENT_MAGIC");

    ESP_GOTO_ON_FALSE(mockClient->currentURL != NULL,
        ESP_ERR_INVALID_STATE, handle_error, TAG, "mockClient->currentURL == NULL");
    ESP_GOTO_ON_FALSE(mockClient->opened,
        ESP_ERR_INVALID_STATE, handle_error, TAG, "!mockClient->opened");

    mockClient->opened = false;
    mockClient->responseNdx = 0;
    return ESP_OK;
handle_error:
    if (failCallback != NULL) failCallback();
    return ret;
}

esp_err_t wrap_esp_http_client_cleanup(esp_http_client_handle_t client)
{
    esp_err_t ret;
    mock_http_client *mockClient;

    /* input guards */
    ESP_GOTO_ON_FALSE(client != NULL,
        ESP_ERR_INVALID_ARG, handle_error, TAG, "client == NULL");

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    ESP_GOTO_ON_FALSE(mockClient->magic == MOCK_CLIENT_MAGIC,
        ESP_ERR_INVALID_ARG, handle_error, TAG, "mockClient->magic == MOCK_CLIENT_MAGIC");

    ESP_GOTO_ON_FALSE(mockClient->currentURL != NULL,
        ESP_ERR_INVALID_STATE, handle_error, TAG, "mockClient->currentURL != NULL");

    free(mockClient);
    return ESP_OK;
handle_error:
    if (failCallback != NULL) failCallback();
    return ret;
}

esp_err_t wrap_esp_http_client_flush_response(esp_http_client_handle_t client, int *len)
{
    esp_err_t ret;
    mock_http_client *mockClient;
    MockHttpEndpoint currEndpoint;
    int endpointNdx;

    /* input guards */
    ESP_GOTO_ON_FALSE(client != NULL,
        ESP_ERR_INVALID_ARG, handle_error, TAG, "client != NULL");

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    ESP_GOTO_ON_FALSE(mockClient->magic == MOCK_CLIENT_MAGIC,
        ESP_ERR_INVALID_ARG, handle_error, TAG, "mockClient->magic == MOCK_CLIENT_MAGIC");

    ESP_GOTO_ON_FALSE(mockClient->currentURL != NULL,
        ESP_ERR_INVALID_STATE, handle_error, TAG, "mockClient->currentURL == NULL");
    ESP_GOTO_ON_FALSE(mockClient->opened,
        ESP_ERR_INVALID_STATE, handle_error, TAG, "!mockClient->opened");

    /* determine endpoint */
    endpointNdx = getEndpointNdx(mockClient->currentURL);
    ESP_GOTO_ON_FALSE(endpointNdx != CONFIG_MAX_NUM_CLIENT_ENDPOINTS,
        ESP_ERR_NOT_FOUND, handle_error, TAG, "endpointNdx != CONFIG_MAX_NUM_CLIENT_ENDPOINTS");
    currEndpoint = endpoints[endpointNdx];

    /* update mockClient pointer to end of endpoint */
    mockClient->responseNdx = currEndpoint.contentLen;

    return ESP_OK;
handle_error:
    if (failCallback != NULL) failCallback();
    return ret;
}