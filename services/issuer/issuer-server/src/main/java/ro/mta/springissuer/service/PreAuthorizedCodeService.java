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
import ro.mta.springissuer.util.authzclient.client.AuthzClient;
import ro.mta.springissuer.util.authzclient.registry.WebClientRegistry;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Service
@Slf4j
public class PreAuthorizedCodeService {

    WebClientRegistry webClientRegistry;

    @Value("${spring.authorization-server.base-url}")
    String springBaseUrl;

    PreAuthorizedCodeService(WebClientRegistry webClientRegistry) {
        this.webClientRegistry = webClientRegistry;
    }

    public Map<String, Object> createPreAuthorizedCode(String userId, List<String> scopes, boolean requirePin) {
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("client_id", "wallet-dev"); // The wallet client ID
        requestBody.put("user_id", userId);
        requestBody.put("require_pin", requirePin);
        requestBody.put("scopes", scopes);

        AuthzClient springAuthzClient = webClientRegistry.getAuthzClient(springBaseUrl);

        try {
            Map response = springAuthzClient
                    .getWebClient()
                    .post()
                    .uri("/credential-offer/create")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + springAuthzClient.getClientSecret())
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


}