package ro.mta.springissuer.util.credential;

import org.springframework.stereotype.Component;
import ro.mta.springissuer.model.credential.Credential;
import ro.mta.springissuer.model.credential.UniversityGraduation;

import java.util.Map;

@Component
public class UnivGradIssuanceStrategy implements CredentialIssuanceStrategy {

    @Override
    public Credential createCredential(Map<String, Object> userDetails, String credentialId) {
        return new UniversityGraduation(userDetails, credentialId);
    }
}
