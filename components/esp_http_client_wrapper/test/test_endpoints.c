/**
 * test_endpoints.c
 * 
 * This file contains unit tests for endpoint functionality of the
 * mock esp_http_client component, contained in wrap_esp_http_client.c
 * 
 * Test file dependencies: None.
 */

#include <stdbool.h>
#include <stddef.h>

#include "unity.h"
#include "sdkconfig.h"

#include "mock_esp_http_client.h"

#ifndef CONFIG_TEST_ESP_HTTP_CLIENT_WRAPPER
#error "esp_http_client_wrapper testing without CONFIG_TEST_ESP_HTTP_CLIENT_WRAPPER set!"
#endif /* CONFIG_TEST_ESP_HTTP_CLIENT_WRAPPER */

#if CONFIG_MAX_NUM_CLIENT_ENDPOINTS != 2
#error "esp_http_client_wrapper tests require CONFIG_MAX_NUM_ENDPOINTS == 2!"
#endif /* CONFIG_MAX_NUM_ENDPOINTS != 2 */

extern MockHttpEndpoint endpoints[CONFIG_MAX_NUM_CLIENT_ENDPOINTS];

TEST_CASE("mock_setup_clearsEndpoints", "[wrap_http_client]")
{
    const char *const urlMagic = (const char *const) 0x12F3;
    const int responseCodeMagic = 246235;
    const char *const responseMagic = (const char *const) 0xF507;
    const size_t contentLenMagic = 3833;

    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        endpoints[i].url = urlMagic;
        endpoints[i].responseCode = responseCodeMagic;
        endpoints[i].response = responseMagic;
        endpoints[i].contentLen = contentLenMagic;
    }

    mock_esp_http_client_setup();

    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        TEST_ASSERT_EQUAL(NULL, endpoints[i].url);
        TEST_ASSERT_EQUAL(0, endpoints[i].responseCode);
        TEST_ASSERT_EQUAL(NULL, endpoints[i].response);
        TEST_ASSERT_EQUAL(0, endpoints[i].contentLen);
    }
}

/**
 * Test case dependencies:
 * - mock_setup_clearsEndpoints
 */
TEST_CASE("mock_add_endpoint_inputGuards", "[wrap_http_client]")
{
    esp_err_t err;
    const char *const response = "Hello, World!";
    MockHttpEndpoint nullURLEndpoint = {
        .url = NULL,
        .responseCode = 200,
        .response = response,
        .contentLen = strlen(response),
    };

    MockHttpEndpoint nullResponseEndpoint = {
        .url = "https://bearanvil.com",
        .responseCode = 200,
        .response = NULL,
        .contentLen = strlen(response),
    };

    mock_esp_http_client_setup();
    err = mock_esp_http_client_add_endpoint(nullURLEndpoint);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, err);
    err = mock_esp_http_client_add_endpoint(nullResponseEndpoint);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, err);

    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        TEST_ASSERT_EQUAL(NULL, endpoints[i].url);
        TEST_ASSERT_EQUAL(0, endpoints[i].responseCode);
        TEST_ASSERT_EQUAL(NULL, endpoints[i].response);
        TEST_ASSERT_EQUAL(0, endpoints[i].contentLen);
    }
}

/**
 * Test case dependencies:
 * - mock_setup_clearsEndpoints
 */
TEST_CASE("mock_add_endpoint_nonExisting", "[wrap_http_client]")
{
    esp_err_t err;
    const char *const response = "Hello, World!";
    MockHttpEndpoint newEndpoint = {
        .url = "https://bearanvil.com",
        .responseCode = 200,
        .response = response,
        .contentLen = strlen(response),
    };

    mock_esp_http_client_setup();
    err = mock_esp_http_client_add_endpoint(newEndpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    bool found = false;
    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        if (endpoints[i].url != NULL && strcmp(endpoints[i].url, newEndpoint.url) == 0)
        {
            TEST_ASSERT_EQUAL(false, found);
            found = true;

            TEST_ASSERT_EQUAL_STRING(endpoints[i].response, newEndpoint.response);
            TEST_ASSERT_EQUAL(endpoints[i].responseCode, newEndpoint.responseCode);
            TEST_ASSERT_EQUAL(endpoints[i].contentLen, newEndpoint.contentLen);
        }
    }
    TEST_ASSERT_EQUAL(true, found);
}

TEST_CASE("mock_add_endpoint_existing", "[wrap_http_client]")
{
    esp_err_t err;
    const char *const response = "Hello, World!";
    MockHttpEndpoint newEndpoint = {
        .url = "https://bearanvil.com",
        .responseCode = 200,
        .response = response,
        .contentLen = strlen(response),
    };

    mock_esp_http_client_setup();
    err = mock_esp_http_client_add_endpoint(newEndpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    err = mock_esp_http_client_add_endpoint(newEndpoint);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, err);

    bool found = false;
    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        if (endpoints[i].url != NULL && strcmp(endpoints[i].url, newEndpoint.url) == 0)
        {
            TEST_ASSERT_EQUAL(false, found);
            found = true;

            TEST_ASSERT_EQUAL_STRING(endpoints[i].response, newEndpoint.response);
            TEST_ASSERT_EQUAL(endpoints[i].responseCode, newEndpoint.responseCode);
            TEST_ASSERT_EQUAL(endpoints[i].contentLen, newEndpoint.contentLen);
        }
    }
    TEST_ASSERT_EQUAL(true, found);
}

/**
 * Test case dependencies:
 *  - mock_add_endpoint_nonExisting
 */
TEST_CASE("mock_add_endpoint_otherExisting", "[wrap_http_client]")
{
    esp_err_t err;
    const char *const response = "Hello, World!";
    MockHttpEndpoint otherEndpoint = {
        .url = "https://bearanvil.com/page1",
        .responseCode = 200,
        .response = response,
        .contentLen = strlen(response),
    };

    MockHttpEndpoint newEndpoint = {
        .url = "https://bearanvil.com",
        .responseCode = 200,
        .response = response,
        .contentLen = strlen(response),
    };

    mock_esp_http_client_setup();
    err = mock_esp_http_client_add_endpoint(otherEndpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    err = mock_esp_http_client_add_endpoint(newEndpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    bool otherFound = false;
    bool newFound = false;
    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        if (endpoints[i].url == NULL) continue;
        if (strcmp(endpoints[i].url, otherEndpoint.url) == 0)
        {
            TEST_ASSERT_EQUAL(false, otherFound);
            otherFound = true;

            TEST_ASSERT_EQUAL_STRING(endpoints[i].response, otherEndpoint.response);
            TEST_ASSERT_EQUAL(endpoints[i].responseCode, otherEndpoint.responseCode);
            TEST_ASSERT_EQUAL(endpoints[i].contentLen, otherEndpoint.contentLen);
        } else if (strcmp(endpoints[i].url, newEndpoint.url) == 0)
        {
            TEST_ASSERT_EQUAL(false, newFound);
            newFound = true;

            TEST_ASSERT_EQUAL_STRING(endpoints[i].response, newEndpoint.response);
            TEST_ASSERT_EQUAL(endpoints[i].responseCode, newEndpoint.responseCode);
            TEST_ASSERT_EQUAL(endpoints[i].contentLen, newEndpoint.contentLen);
        }
    }
    TEST_ASSERT_EQUAL(true, otherFound);
    TEST_ASSERT_EQUAL(true, newFound);
}

/**
 * Test case dependencies:
 *  - mock_add_endpoint_otherExisting
 */
TEST_CASE("mock_add_endpoint_tooManyEndpoints", "[wrap_http_client]")
{
    esp_err_t err;
    const char *const response = "Hello, World!";
    MockHttpEndpoint otherEndpoint = {
        .url = "https://bearanvil.com/page1",
        .responseCode = 200,
        .response = response,
        .contentLen = strlen(response),
    };

    MockHttpEndpoint newEndpoint = {
        .url = "https://bearanvil.com",
        .responseCode = 200,
        .response = response,
        .contentLen = strlen(response),
    };

    MockHttpEndpoint anotherEndpoint = {
        .url = "https://bearanvil.com/page2",
        .responseCode = 200,
        .response = response,
        .contentLen = strlen(response),
    };

    mock_esp_http_client_setup();
    err = mock_esp_http_client_add_endpoint(otherEndpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    err = mock_esp_http_client_add_endpoint(newEndpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    err = mock_esp_http_client_add_endpoint(anotherEndpoint);
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, err);

    bool found = false;
    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        if (endpoints[i].url != NULL && strcmp(endpoints[i].url, newEndpoint.url) == 0)
        {
            TEST_ASSERT_EQUAL(false, found);
            found = true;

            TEST_ASSERT_EQUAL_STRING(endpoints[i].response, newEndpoint.response);
            TEST_ASSERT_EQUAL(endpoints[i].responseCode, newEndpoint.responseCode);
            TEST_ASSERT_EQUAL(endpoints[i].contentLen, newEndpoint.contentLen);
        }
    }
    TEST_ASSERT_EQUAL(true, found);
}

/**
 * Test case dependencies:
 * - mock_setup_clearsEndpoints
 */
TEST_CASE("mock_remove_endpoint_inputGuards", "[wrap_http_client]")
{
    esp_err_t err;

    mock_esp_http_client_setup();
    err = mock_esp_http_client_remove_endpoint(NULL);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, err);

    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        TEST_ASSERT_EQUAL(NULL, endpoints[i].url);
        TEST_ASSERT_EQUAL(0, endpoints[i].responseCode);
        TEST_ASSERT_EQUAL(NULL, endpoints[i].response);
        TEST_ASSERT_EQUAL(0, endpoints[i].contentLen);
    }
}

/**
 * Test case dependencies:
 * - mock_setup_clearsEndpoints
 */
TEST_CASE("mock_remove_endpoint_nonExisting", "[wrap_http_client]")
{
    esp_err_t err;

    mock_esp_http_client_setup();
    err = mock_esp_http_client_remove_endpoint("https://bearanvil.com");
    TEST_ASSERT_EQUAL(ESP_ERR_NOT_FOUND, err);

    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        TEST_ASSERT_EQUAL(NULL, endpoints[i].url);
        TEST_ASSERT_EQUAL(0, endpoints[i].responseCode);
        TEST_ASSERT_EQUAL(NULL, endpoints[i].response);
        TEST_ASSERT_EQUAL(0, endpoints[i].contentLen);
    }
}

/**
 * Test case dependencies:
 *  - mock_add_endpoint_nonExisting
 */
TEST_CASE("mock_remove_endpoint_existing", "[wrap_http_client]")
{
    esp_err_t err;
    const char *const response = "Hello, World!";
    MockHttpEndpoint newEndpoint = {
        .url = "https://bearanvil.com",
        .responseCode = 200,
        .response = response,
        .contentLen = strlen(response),
    };

    mock_esp_http_client_setup();
    err = mock_esp_http_client_add_endpoint(newEndpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    err = mock_esp_http_client_remove_endpoint(newEndpoint.url);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        if (endpoints[i].url != NULL && strcmp(endpoints[i].url, newEndpoint.url) == 0)
        {
            TEST_FAIL_MESSAGE("Unexpectedly found removed endpoint.");
        }
    }
}

/**
 * Test case dependencies:
 *  - mock_add_endpoint_otherExisting
 */
TEST_CASE("mock_remove_endpoint_otherExisting", "[wrap_http_client]")
{
    esp_err_t err;
    const char *const response = "Hello, World!";
    MockHttpEndpoint otherEndpoint = {
        .url = "https://bearanvil.com/page1",
        .responseCode = 200,
        .response = response,
        .contentLen = strlen(response),
    };

    MockHttpEndpoint newEndpoint = {
        .url = "https://bearanvil.com",
        .responseCode = 200,
        .response = response,
        .contentLen = strlen(response),
    };

    mock_esp_http_client_setup();
    err = mock_esp_http_client_add_endpoint(otherEndpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    err = mock_esp_http_client_add_endpoint(newEndpoint);
    TEST_ASSERT_EQUAL(ESP_OK, err);
    err = mock_esp_http_client_remove_endpoint(newEndpoint.url);
    TEST_ASSERT_EQUAL(ESP_OK, err);

    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        if (endpoints[i].url != NULL && strcmp(endpoints[i].url, newEndpoint.url) == 0)
        {
            TEST_FAIL_MESSAGE("Unexpectedly found removed endpoint.");
        }
    }

    bool otherFound = false;
    for (int i = 0; i < CONFIG_MAX_NUM_CLIENT_ENDPOINTS; i++)
    {
        if (endpoints[i].url != NULL && strcmp(endpoints[i].url, otherEndpoint.url) == 0)
        {
            TEST_ASSERT_EQUAL(false, otherFound);
            otherFound = true;

            TEST_ASSERT_EQUAL_STRING(endpoints[i].response, otherEndpoint.response);
            TEST_ASSERT_EQUAL(endpoints[i].responseCode, otherEndpoint.responseCode);
            TEST_ASSERT_EQUAL(endpoints[i].contentLen, otherEndpoint.contentLen);
        }
        if (endpoints[i].url != NULL && strcmp(endpoints[i].url, newEndpoint.url) == 0)
        {
            TEST_FAIL_MESSAGE("Unexpectedly found removed endpoint.");
        }
    }
    TEST_ASSERT_EQUAL(true, otherFound);
}
