package ro.mta.springissuer.util.credential;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Component
public class StrategyRegistry {
    private final Map<String, CredentialIssuanceStrategy> strategies = new HashMap<>();

    public void register(String vct, CredentialIssuanceStrategy strategy) {
        strategies.put(vct, strategy);
    }

    public CredentialIssuanceStrategy getStrategy(String vct) {
        CredentialIssuanceStrategy strategy = strategies.get(vct);
        if (strategy == null) {
            throw new IllegalArgumentException("Unknown strategy: " + vct);
        }
        return strategy;
    }

    public boolean supports(String vct) {
        return strategies.containsKey(vct);
    }

    public Set<String> getRegisteredVcts() {
        return strategies.keySet();
    }

    public void unregister(String vct) {
        strategies.remove(vct);
    }
}
