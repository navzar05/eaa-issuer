package ro.mta.springissuer.util.credential;

import org.springframework.security.oauth2.jwt.Jwt;
import ro.mta.springissuer.model.credential.Credential;
import ro.mta.springissuer.model.request.CredentialRequest;

import java.util.Map;

public interface CredentialIssuanceStrategy {

    public Credential createCredential(Map<String, Object> userDetails, String credentialId);
}