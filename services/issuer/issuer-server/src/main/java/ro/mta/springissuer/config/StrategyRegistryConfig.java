package ro.mta.springissuer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ro.mta.springissuer.util.credential.PidIssuanceStrategy;
import ro.mta.springissuer.util.credential.StrategyRegistry;
import ro.mta.springissuer.util.credential.UnivGradIssuanceStrategy;

@Configuration
public class StrategyRegistryConfig {

    @Bean
    public StrategyRegistry strategyRegistry(
            PidIssuanceStrategy pidIssuanceStrategy,
            UnivGradIssuanceStrategy univGradIssuanceStrategy
    ) {
        StrategyRegistry strategyRegistry = new StrategyRegistry();
        strategyRegistry.register("urn:eu.europa.ec.eudi:pid:1", pidIssuanceStrategy);
        strategyRegistry.register("urn:org:certsign:university:graduation:1", univGradIssuanceStrategy);

        return strategyRegistry;
    }
}
