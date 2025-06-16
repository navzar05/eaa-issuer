package ro.mta.springissuer.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@Service
public class UserInfoService {

    private static final Logger logger = LoggerFactory.getLogger(UserInfoService.class);

    private final WebClient springAuthzWebClient;
    private final WebClient keycloakWebClient;
    private final String adminUrl;
    private final String clientId;
    private final String clientSecret;
    private final String tokenUrl;
    private final String baseUrl;

    // Spring Authorization Server configuration
    private final String springAuthzTokenUrl;
    private final String keycloakIssuerUri;
    private final String springAuthzIssuerUri;

    public UserInfoService(
            @Qualifier("keycloakWebClient") WebClient keycloakWebClient,
            @Qualifier("springAuthzWebClient") WebClient springAuthzWebClient,
            @Value("${keycloak.base-url}/admin/realms/pid-issuer-realm/users") String adminUrl,
            @Value("${keycloak.pid-issuer-srv.client-id}") String clientId,
            @Value("${keycloak.pid-issuer-srv.client-secret}") String clientSecret,
            @Value("${keycloak.base-url}/realms/pid-issuer-realm/protocol/openid-connect/token") String tokenUrl,
            @Value("${keycloak.base-url}") String baseUrl,
            @Value("${spring.security.oauth2.resourceserver.jwt.keycloak.issuer-uri}") String keycloakIssuerUri,
            @Value("${spring.security.oauth2.resourceserver.jwt.spring-authz.issuer-uri}") String springAuthzIssuerUri) {
        this.keycloakWebClient = keycloakWebClient;
        this.springAuthzWebClient = springAuthzWebClient;
        this.adminUrl = adminUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenUrl = tokenUrl;
        this.baseUrl = baseUrl;
        this.springAuthzTokenUrl = springAuthzIssuerUri + "/oauth2/token";
        this.keycloakIssuerUri = keycloakIssuerUri;
        this.springAuthzIssuerUri = springAuthzIssuerUri;
    }

    /**
     * Obține access token de admin pentru Keycloak
     */
    private String getAdminAccessTokenKeycloak() {
        logger.debug("Obtaining admin access token from Keycloak");

        Mono<Map> tokenResponse = keycloakWebClient.post()
                .uri(tokenUrl)
                .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue("grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + clientSecret)
                .retrieve()
                .bodyToMono(Map.class);

        Map<String, Object> response = tokenResponse.block();
        if (response == null || !response.containsKey("access_token")) {
            throw new RuntimeException("Failed to obtain Keycloak admin access token");
        }
        return (String) response.get("access_token");
    }

    /**
     * Obține access token de admin pentru Spring Authorization Server
     */

    private String getAdminAccessTokenSpring() {
        logger.debug("Obtaining admin access token from Spring Authorization Server");

        // Encode client credentials for Basic Auth
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = java.util.Base64.getEncoder().encodeToString(credentials.getBytes());

        Mono<Map> tokenResponse = springAuthzWebClient.post()
                .uri("/oauth2/token")
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

    /**
     * Obține detaliile utilizatorului în funcție de issuer-ul JWT-ului
     */
    public Map<String, Object> getUserDetails(Jwt jwt) {
        String userId = jwt.getClaim("sub");
        String issuer = jwt.getIssuer().toString();

        logger.debug("Fetching user details for userId: {} from issuer: {}", userId, issuer);

        Mono<Map> responseMono;

        if (springAuthzIssuerUri.equals(issuer)) {
            // Pentru Spring Authorization Server, folosim admin endpoint-ul custom
            logger.debug("Using Spring Authorization Server admin endpoint for user info");
            String adminToken = getAdminAccessTokenSpring();

            responseMono = springAuthzWebClient.get()
                    .uri("/service/userinfo/" + userId)
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
        } else if (keycloakIssuerUri.equals(issuer)) {
            // Pentru Keycloak, folosim admin API
            logger.debug("Using Keycloak for user info");
            String adminToken = getAdminAccessTokenKeycloak();

            responseMono = keycloakWebClient.get()
                    .uri(adminUrl + "/" + userId)
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

            // Pentru Keycloak, încercăm să ștergem consent-ul
            try {
                deleteUserConsent(userId, adminToken);
            } catch (Exception ex) {
                logger.warn("Failed to delete user consent for userId {}: {}", userId, ex.getMessage());
            }
        } else {
            throw new IllegalArgumentException("Unknown issuer: " + issuer);
        }
        Map response = responseMono.block();
        if (response == null) {
            throw new RuntimeException("User details response is null");
        }

        return response;
    }

    /**
     * Șterge consent-ul utilizatorului din Keycloak (doar pentru Keycloak)
     */
    private void deleteUserConsent(String userId, String adminToken) {
        logger.debug("Deleting user consent for userId: {}", userId);

        try {
            String deleteConsentsUrl = baseUrl + "/admin/realms/pid-issuer-realm/users/" + userId + "/consents/wallet-dev";

            keycloakWebClient.delete()
                    .uri(deleteConsentsUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
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

    /**
     * Determină tipul de credential în funcție de issuer
     */
    public CredentialType getCredentialType(Jwt jwt) {
        String issuer = jwt.getIssuer().toString();

        if (keycloakIssuerUri.equals(issuer)) {
            return CredentialType.PID;
        } else if (springAuthzIssuerUri.equals(issuer)) {
            return CredentialType.UNIVERSITY_GRADUATION;
        } else {
            throw new IllegalArgumentException("Unknown issuer: " + issuer);
        }
    }

    /**
     * Enum pentru tipurile de credentiale suportate
     */
    public enum CredentialType {
        PID("eu.europa.ec.eudi.pid_vc_sd_jwt"),
        UNIVERSITY_GRADUATION("org.certsign.university_graduation_sdjwt");

        private final String scope;

        CredentialType(String scope) {
            this.scope = scope;
        }

        public String getScope() {
            return scope;
        }
    }
}