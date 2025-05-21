/**
 * wrap_esp_http_client.c
 * 
 * Contains mock control functions that implement mock_esp_http_client.h
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "esp_http_client.h"
#include "sdkconfig.h"

#include "wrap_esp_http_client_internal.h"
#include "mock_esp_http_client.h"

#ifdef CONFIG_TEST_ESP_HTTP_CLIENT_WRAPPER
#define STATIC_IF_NOT_TEST 
#else
#define STATIC_IF_NOT_TEST static
#endif /* CONFIG_TEST_ESP_HTTP_CLIENT_WRAPPER */

#define MOCK_CLIENT_MAGIC 0x49A5

typedef struct {
    bool opened;
    const char *currentURL;
    size_t responseNdx;
    int magic; // to ensure the esp_http_client_handle_t is actually a mock
} mock_http_client;

STATIC_IF_NOT_TEST MockHttpEndpoint endpoints[CONFIG_MAX_NUM_CLIENT_ENDPOINTS];

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
 * @note This clears any existing endpoints.
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
    mock_http_client *mockClient;
    
    /* input guards */
    if (config == NULL) return NULL;
    if (config->url == NULL) return NULL;

    /* allocate and create mock client */
    mockClient = malloc(sizeof(mock_http_client));
    if (mockClient == NULL) return NULL;

    mockClient->currentURL = config->url;
    mockClient->opened = false;
    mockClient->responseNdx = 0;
    mockClient->magic = MOCK_CLIENT_MAGIC;

    return (esp_http_client_handle_t) mockClient;
}

esp_err_t wrap_esp_http_client_set_url(esp_http_client_handle_t client, const char *url)
{
    mock_http_client *mockClient;

    /* input guards */
    if (client == NULL) return ESP_ERR_INVALID_ARG;
    if (url == NULL) return ESP_ERR_INVALID_ARG;

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    if (mockClient->magic != MOCK_CLIENT_MAGIC) return ESP_ERR_INVALID_ARG;
    if (mockClient->opened) return ESP_ERR_INVALID_STATE;

    /* set url */
    mockClient->currentURL = url;
    mockClient->responseNdx = 0;
    return ESP_OK;
}

esp_err_t wrap_esp_http_client_open(esp_http_client_handle_t client, int write_len)
{
    mock_http_client *mockClient;
    /* input guards */
    if (client == NULL) return ESP_ERR_INVALID_ARG;
    if (write_len != 0) return ESP_ERR_NOT_SUPPORTED; // TODO: support writing

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    if (mockClient->magic != MOCK_CLIENT_MAGIC) return ESP_ERR_INVALID_ARG;

    /* open mock client */
    if (mockClient->opened) return ESP_ERR_INVALID_STATE;
    mockClient->opened = true;
    mockClient->responseNdx = 0;
    return ESP_OK;
}

int wrap_esp_http_client_get_status_code(esp_http_client_handle_t client)
{
    mock_http_client *mockClient;
    int endpointNdx;

    /* input guards */
    if (client == NULL) return ESP_ERR_INVALID_ARG;

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    if (mockClient->magic != MOCK_CLIENT_MAGIC) return ESP_ERR_INVALID_ARG;
    if (mockClient->currentURL == NULL) return ESP_ERR_INVALID_STATE;
    if (!mockClient->opened) return ESP_ERR_INVALID_STATE;

    /* retrieve status code */
    endpointNdx = getEndpointNdx(mockClient->currentURL);
    if (endpointNdx >= CONFIG_MAX_NUM_CLIENT_ENDPOINTS) return ESP_ERR_NOT_FOUND;
    return endpoints[endpointNdx].responseCode;
}

int64_t wrap_esp_http_client_get_content_length(esp_http_client_handle_t client)
{
    mock_http_client *mockClient;
    int endpointNdx;

    /* input guards */
    if (client == NULL) return ESP_ERR_INVALID_ARG;

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    if (mockClient->magic != MOCK_CLIENT_MAGIC) return ESP_ERR_INVALID_ARG;
    if (mockClient->currentURL == NULL) return ESP_ERR_INVALID_STATE;
    if (!mockClient->opened) return ESP_ERR_INVALID_STATE;

    /* retrieve status code */
    endpointNdx = getEndpointNdx(mockClient->currentURL);
    if (endpointNdx >= CONFIG_MAX_NUM_CLIENT_ENDPOINTS) return ESP_ERR_NOT_FOUND;
    return endpoints[endpointNdx].contentLen;
}

int wrap_esp_http_client_read(esp_http_client_handle_t client, char *buffer, int len)
{
    mock_http_client *mockClient;
    MockHttpEndpoint currEndpoint;
    int endpointNdx;
    int readLen;

    /* input guards */
    if (client == NULL) return ESP_ERR_INVALID_ARG;
    if (len == 0) return ESP_ERR_INVALID_ARG;

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    if (mockClient->magic != MOCK_CLIENT_MAGIC) return ESP_ERR_INVALID_ARG;

    if (mockClient->currentURL == NULL) return ESP_ERR_INVALID_STATE;
    if (!mockClient->opened) return ESP_ERR_INVALID_STATE;   

    /* determine endpoint */
    endpointNdx = getEndpointNdx(mockClient->currentURL);
    if (endpointNdx == CONFIG_MAX_NUM_CLIENT_ENDPOINTS) return ESP_ERR_NOT_FOUND;
    currEndpoint = endpoints[endpointNdx];

    /* continue reading from response */
    if (mockClient->responseNdx >= currEndpoint.contentLen) return ESP_ERR_INVALID_STATE;
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
}

esp_err_t wrap_esp_http_client_close(esp_http_client_handle_t client)
{
    mock_http_client *mockClient;
    int endpointNdx;

    /* input guards */
    if (client == NULL) return ESP_ERR_INVALID_ARG;

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    if (mockClient->magic != MOCK_CLIENT_MAGIC) return ESP_ERR_INVALID_ARG;

    if (mockClient->currentURL == NULL) return ESP_ERR_INVALID_STATE;
    if (!mockClient->opened) return ESP_ERR_INVALID_STATE;

    mockClient->opened = false;
    mockClient->responseNdx = 0;
    return ESP_OK;
}

esp_err_t wrap_esp_http_client_cleanup(esp_http_client_handle_t client)
{
    mock_http_client *mockClient;
    int endpointNdx;

    /* input guards */
    if (client == NULL) return ESP_ERR_INVALID_ARG;

    /* ensure client is actually a mock */
    mockClient = (mock_http_client *) client;
    if (mockClient->magic != MOCK_CLIENT_MAGIC) return ESP_ERR_INVALID_ARG;

    if (mockClient->currentURL == NULL) return ESP_ERR_INVALID_STATE;

    free(mockClient);
    return ESP_OK;
}