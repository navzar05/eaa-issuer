package ro.mta.springissuer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configurările de securitate pentru server-ul de atestări.
 * Această clasă definește regulile de autorizare și autentificare
 * pentru toate endpoint-urile aplicației.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configurează lanțul de filtre de securitate pentru aplicație.
     * Definește care endpoint-uri sunt publice și care necesită autentificare,
     * precum și tipul de autentificare folosit (JWT prin OAuth2).
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
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }
}