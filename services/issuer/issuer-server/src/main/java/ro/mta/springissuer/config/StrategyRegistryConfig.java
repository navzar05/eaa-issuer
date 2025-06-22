package ro.mta.springissuer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ro.mta.springissuer.util.credential.PidIssuanceStrategy;
import ro.mta.springissuer.util.credential.StrategyRegistry;
import ro.mta.springissuer.util.credential.UnivGradIssuanceStrategy;


/**
 * Registru pentru strategiile de creare a SD-JWT-urilor
 * în funcție de informațiile primite de la sursa autentică.
 */
@Configuration
public class StrategyRegistryConfig {

    @Bean
    public StrategyRegistry strategyRegistry(
            PidIssuanceStrategy pidStrategy,
            UnivGradIssuanceStrategy gradStrategy) {

        StrategyRegistry registry = new StrategyRegistry();
        registry.register("urn:eu.europa.ec.eudi:pid:1", pidStrategy);
        registry.register("urn:org:certsign:university:graduation:1", gradStrategy);

        return registry;
    }
}