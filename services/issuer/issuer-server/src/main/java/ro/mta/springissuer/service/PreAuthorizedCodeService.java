package ro.mta.springissuer.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Service
@Slf4j
public class PreAuthorizedCodeService {

    @Qualifier("springAuthzWebClient")
    private final WebClient springAuthzWebClient;


    @Value("${issuer.client.id:issuer-srv}")
    private String clientId;

    @Value("${issuer.client.secret:zIKAV9DIIIaJCzHCVBPlySgU8KgY68U2}")
    private String clientSecret;

    PreAuthorizedCodeService(@Qualifier("springAuthzWebClient") WebClient webClient) {
        this.springAuthzWebClient = webClient;
    }

    public Map<String, Object> createPreAuthorizedCode(String userId, List<String> scopes, boolean requirePin) {
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("client_id", "wallet-dev"); // The wallet client ID
        requestBody.put("user_id", userId);
        requestBody.put("require_pin", requirePin);
        requestBody.put("scopes", scopes);

        String adminToken = getAdminAccessTokenSpring();

        try {
            Map response = springAuthzWebClient
                    .post()
                    .uri("/credential-offer/create")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();


            log.info("Created pre-authorized code for user: {}", userId);
            return response;

        } catch (Exception e) {
            log.error("Failed to create pre-authorized code for user: {}", userId, e);
            throw new RuntimeException("Failed to create pre-authorized code", e);
        }
    }

    private String getAdminAccessTokenSpring() {
        log.debug("Obtaining admin access token from Spring Authorization Server");

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

}