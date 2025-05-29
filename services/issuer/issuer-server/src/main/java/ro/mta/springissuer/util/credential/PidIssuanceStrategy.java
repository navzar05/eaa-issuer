package ro.mta.springissuer.util.credential;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import ro.mta.springissuer.model.credential.Credential;
import ro.mta.springissuer.model.credential.Pid;
import ro.mta.springissuer.model.request.CredentialRequest;

import java.util.Map;

@Component
public class PidIssuanceStrategy implements CredentialIssuanceStrategy {

    @Override
    public Credential createCredential(Map<String, Object> userDetails, String credentialId) {
        return new Pid(userDetails, credentialId);
    }
}