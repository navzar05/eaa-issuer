package ro.mta.springissuer.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Service
public class UserInfoService {

    private static final Logger logger = LoggerFactory.getLogger(UserInfoService.class);

    private final WebClient keycloakWebClient;
    private final String adminUrl;
    private final String clientId;
    private final String clientSecret;
    private final String tokenUrl;
    private final String baseUrl;

    public UserInfoService(
            @Qualifier("keycloakWebClient") WebClient keycloakWebClient,
            @Value("${keycloak.base-url}/admin/realms/pid-issuer-realm/users") String adminUrl,
            @Value("${keycloak.pid-issuer-srv.client-id}") String clientId,
            @Value("${keycloak.pid-issuer-srv.client-secret}") String clientSecret,
            @Value("${keycloak.base-url}/realms/pid-issuer-realm/protocol/openid-connect/token") String tokenUrl,
            @Value("${keycloak.base-url}") String baseUrl) {
        this.keycloakWebClient = keycloakWebClient;
        this.adminUrl = adminUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenUrl = tokenUrl;
        this.baseUrl = baseUrl;
    }

    private String getAdminAccessToken() {
        Mono<Map> tokenResponse = keycloakWebClient.post()
                .uri(tokenUrl)
                .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue("grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + clientSecret)
                .retrieve()
                .bodyToMono(Map.class);

        Map<String, Object> response = tokenResponse.block();
        if (response == null || !response.containsKey("access_token")) {
            throw new RuntimeException("Failed to obtain admin access token");
        }
        return (String) response.get("access_token");
    }

    public Map<String, Object> getUserDetails(Jwt jwt) {
        String userId = jwt.getClaim("sub");
        String adminToken = getAdminAccessToken();

        logger.debug("Fetching user details for userId: {}", userId);

        // First, get user details
        Mono<Map> responseMono = keycloakWebClient.get()
                .uri(adminUrl + "/" + userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .retrieve()
                .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                        response -> response.bodyToMono(String.class)
                                .map(body -> new RuntimeException("HTTP " + response.statusCode() + ": " + body)))
                .bodyToMono(Map.class)
                .doOnSuccess(response -> logger.info("User details retrieved successfully"))
                .onErrorMap(ex -> {
                    logger.error("Error fetching user details: {}", ex.getMessage());
                    return new RuntimeException("Failed to fetch user details: " + ex.getMessage(), ex);
                });

        Map<String, Object> response = responseMono.block();
        if (response == null) {
            throw new RuntimeException("User details response is null");
        }

        // After successfully retrieving user details, delete user consent
        try {
            deleteUserConsent(userId, adminToken);
        } catch (Exception ex) {
            logger.warn("Failed to delete user consent for userId {}: {}", userId, ex.getMessage());
            // Don't fail the entire operation if consent deletion fails
        }

        return response;
    }

    private void deleteUserConsent(String userId, String adminToken) {
        logger.debug("Deleting user consent for userId: {}", userId);

        try {
            // First, get all consents for the user
            String consentsUrl = baseUrl + "/admin/realms/pid-issuer-realm/users/" + userId + "/consents";

            Mono<List> consentsMono = keycloakWebClient.get()
                    .uri(consentsUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .retrieve()
                    .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                            response -> response.bodyToMono(String.class)
                                    .map(body -> new RuntimeException("HTTP " + response.statusCode() + ": " + body)))
                    .bodyToMono(List.class);

            List<Map<String, Object>> consents = consentsMono.block();

            if (consents != null && !consents.isEmpty()) {
                // Delete each consent
                for (Map<String, Object> consent : consents) {
                    String clientId = (String) consent.get("clientId");
                    if (clientId != null) {
                        deleteSpecificConsent(userId, clientId, adminToken);
                    }
                }
                logger.info("Successfully deleted all consents for userId: {}", userId);
            } else {
                logger.debug("No consents found for userId: {}", userId);
            }

        } catch (Exception ex) {
            logger.error("Error deleting user consent for userId {}: {}", userId, ex.getMessage());
            throw new RuntimeException("Failed to delete user consent", ex);
        }
    }

    private void deleteSpecificConsent(String userId, String clientId, String adminToken) {
        String deleteUrl = baseUrl + "/admin/realms/pid-issuer-realm/users/" + userId + "/consents/" + clientId;

        try {
            keycloakWebClient.delete()
                    .uri(deleteUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .retrieve()
                    .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                            response -> response.bodyToMono(String.class)
                                    .map(body -> new RuntimeException("HTTP " + response.statusCode() + ": " + body)))
                    .bodyToMono(Void.class)
                    .block();

            logger.debug("Successfully deleted consent for userId: {} and clientId: {}", userId, clientId);

        } catch (Exception ex) {
            logger.error("Error deleting specific consent for userId {} and clientId {}: {}",
                    userId, clientId, ex.getMessage());
            throw ex;
        }
    }
}