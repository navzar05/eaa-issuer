package ro.mta.springissuer.util.authzclient.client;

import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import reactor.core.publisher.Mono;

import java.util.Map;

public class AuthzClientSpring extends AuthzClient {

    public AuthzClientSpring(String baseUrl,
                               String clientId,
                               String clientSecret,
                               String tokenUrl,
                               String adminUrl,
                             Resource trustStore,
                             String trustStorePassword) {
        super(baseUrl, clientId, clientSecret, tokenUrl, adminUrl, trustStore, trustStorePassword);
    }


    @Override
    protected String getAdminToken() {
        logger.debug("Obtaining admin access token from Spring Authorization Server");

        // Encode client credentials for Basic Auth
        String credentials = this.getClientId() + ":" + "zIKAV9DIIIaJCzHCVBPlySgU8KgY68U2";
        String encodedCredentials = java.util.Base64.getEncoder().encodeToString(credentials.getBytes());

        Mono<Map> tokenResponse = this.getWebClient().post()
                .uri(this.getTokenUrl())
                .header(HttpHeaders.AUTHORIZATION, "Basic " + encodedCredentials)
                .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue("grant_type=client_credentials&scope=issuer:credentials")
                .retrieve()
                .bodyToMono(Map.class);

        Map<String, Object> response = tokenResponse.block();
        if (response == null || !response.containsKey("access_token")) {
            throw new RuntimeException("Failed to obtain Spring Authorization Server admin access token");
        }
        return (String) response.get("access_token");
    }

    @Override
    public Map<String, Object> getUserDetails(String userId) {
        String adminToken = getAdminToken();

        Mono<Map> responseMono = this.getWebClient().get()
                .uri(this.getAdminUrl() + userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .retrieve()
                .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                        response -> response.bodyToMono(String.class)
                                .map(body -> new RuntimeException("HTTP " + response.statusCode() + ": " + body)))
                .bodyToMono(Map.class)
                .doOnSuccess(response -> logger.info("User details retrieved successfully from Spring AuthZ admin endpoint"))
                .onErrorMap(ex -> {
                    logger.error("Error fetching user details from Spring AuthZ: {}", ex.getMessage());
                    return new RuntimeException("Failed to fetch user details from Spring AuthZ: " + ex.getMessage(), ex);
                });
        Map response = responseMono.block();
        if (response == null) {
            throw new RuntimeException("User details response is null");
        }

        return response;
    }
}
