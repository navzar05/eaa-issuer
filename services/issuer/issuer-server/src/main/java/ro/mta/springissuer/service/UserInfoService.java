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
import ro.mta.springissuer.util.authzclient.client.AuthzClient;
import ro.mta.springissuer.util.authzclient.registry.WebClientRegistry;

import java.util.Map;

@Service
public class UserInfoService {

    private final WebClientRegistry webClientRegistry;

    public UserInfoService(WebClientRegistry webClientRegistry) {
        this.webClientRegistry = webClientRegistry;
    }

    public Map<String, Object> getUserInfo(Jwt jwt) {
        String issuer = String.valueOf(jwt.getIssuer());
        String userId = jwt.getSubject();

        AuthzClient authzClient = webClientRegistry.getAuthzClient(issuer);

        return authzClient.getUserDetails(userId);
    }

}