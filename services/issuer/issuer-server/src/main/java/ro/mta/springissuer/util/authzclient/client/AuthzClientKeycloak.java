package ro.mta.springissuer.util.authzclient.client;

import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import reactor.core.publisher.Mono;

import java.util.Map;

public class AuthzClientKeycloak extends AuthzClient {

    public AuthzClientKeycloak(String baseUrl,
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
        logger.debug("Obtaining admin access token from Keycloak");

        Mono<Map> tokenResponse = this.getWebClient().post()
                .uri(this.getTokenUrl())
                .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue("grant_type=client_credentials&client_id=" +
                        this.getClientId() +
                        "&client_secret=" +
                        this.getClientSecret())
                .retrieve()
                .bodyToMono(Map.class);

        Map<String, Object> response = tokenResponse.block();
        if (response == null || !response.containsKey("access_token")) {
            throw new RuntimeException("Failed to obtain Keycloak admin access token");
        }
        return (String) response.get("access_token");
    }

    @Override
    public Map<String, Object> getUserDetails(String userId) {
        logger.debug("Using Keycloak for user info");
        String adminToken = getAdminToken();

        Mono<Map> responseMono = this.getWebClient().get()
                .uri(this.getAdminUrl() + "/" + userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .retrieve()
                .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                        response -> response.bodyToMono(String.class)
                                .map(body -> new RuntimeException("HTTP " + response.statusCode() + ": " + body)))
                .bodyToMono(Map.class)
                .doOnSuccess(response -> logger.info("User details retrieved successfully from Keycloak"))
                .onErrorMap(ex -> {
                    logger.error("Error fetching user details from Keycloak: {}", ex.getMessage());
                    return new RuntimeException("Failed to fetch user details from Keycloak: " + ex.getMessage(), ex);
                });



        Map response = responseMono.block();
        if(response ==null)
            throw new RuntimeException("User details response is null");

        try {
            deleteUserConsent(userId);
        } catch (Exception ex) {
            logger.warn("Failed to delete user consent for userId {}: {}", userId, ex.getMessage());
        }

        return response;
    }

    private void deleteUserConsent(String userId) {
    logger.debug("Deleting user consent for userId: {}", userId);

    try {
        String deleteConsentsUrl = this.getAdminUrl() + "/admin/realms/pid-issuer-realm/users/" + userId + "/consents/wallet-dev";

        this.getWebClient().delete()
                .uri(deleteConsentsUrl)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + this.getAdminToken())
                .retrieve()
                .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                        response -> response.bodyToMono(String.class)
                                .map(body -> new RuntimeException("HTTP " + response.statusCode() + ": " + body)))
                .bodyToMono(Void.class)
                .block();

        logger.info("Successfully deleted all consents for userId: {}", userId);

    } catch (Exception ex) {
        logger.error("Error deleting user consent for userId {}: {}", userId, ex.getMessage());
        throw new RuntimeException("Failed to delete user consent", ex);
    }
}
}
