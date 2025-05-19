This repo contains an ESP-IDF component that wraps esp_http_client and a useable mock of the component that is enabled
via Kconfig options. The component is designed to be used instead of esp_http_client in any cases where mocking of the
client is required. This allows your components to mock esp_http_client, while maintaining ESP-IDF component's ability
to work correctly. It does not use CMock, rather it uses a custom implementation that may not keep up-to-date with
the esp_http_client component.
