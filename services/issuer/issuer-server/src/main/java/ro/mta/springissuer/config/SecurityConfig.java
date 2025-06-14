package ro.mta.springissuer.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Configurările de securitate pentru server-ul de atestări.
 * Această clasă definește regulile de autorizare și autentificare
 * pentru toate endpoint-urile aplicației cu suport pentru multiple authorization servers.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.keycloak.issuer-uri}")
    private String keycloakIssuerUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.spring-authz.issuer-uri}")
    private String springAuthzIssuerUri;

    /**
     * Configurează lanțul de filtre de securitate pentru aplicație.
     * Definește care endpoint-uri sunt publice și care necesită autentificare,
     * precum și tipul de autentificare folosit (JWT prin OAuth2) cu suport pentru multiple issuers.
     *
     * @param http obiectul HttpSecurity folosit pentru configurarea securității
     * @return SecurityFilterChain configurat
     * @throws Exception în cazul în care configurarea eșuează
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/issuer-server/.well-known/**").permitAll()
                        .requestMatchers("/public/**").permitAll()
                        .requestMatchers("/revocation-list").permitAll()
                        .requestMatchers("/revocation-list-ipfs").permitAll()
                        .requestMatchers("/issuer-server/wallet/offer/qr").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .authenticationManagerResolver(authenticationManagerResolver())
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    /**
     * Configurează resolver-ul pentru multiple authorization servers.
     * Permite aplicației să accepte JWT-uri de la mai mulți issuers.
     *
     * @return AuthenticationManagerResolver configurat
     */
    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
        Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();

        // Keycloak authentication manager
        JwtDecoder keycloakDecoder = JwtDecoders.fromIssuerLocation(keycloakIssuerUri);
        JwtAuthenticationProvider keycloakProvider = new JwtAuthenticationProvider(keycloakDecoder);
        authenticationManagers.put(keycloakIssuerUri, keycloakProvider::authenticate);

        // Spring Authorization Server authentication manager
        JwtDecoder springDecoder = JwtDecoders.fromIssuerLocation(springAuthzIssuerUri);
        JwtAuthenticationProvider springProvider = new JwtAuthenticationProvider(springDecoder);
        authenticationManagers.put(springAuthzIssuerUri, springProvider::authenticate);

        return new JwtIssuerAuthenticationManagerResolver(authenticationManagers::get);
    }
}