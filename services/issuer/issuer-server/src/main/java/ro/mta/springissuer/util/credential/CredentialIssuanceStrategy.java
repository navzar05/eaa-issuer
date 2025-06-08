package ro.mta.springissuer.util.credential;

import org.springframework.security.oauth2.jwt.Jwt;
import ro.mta.springissuer.model.credential.Credential;
import ro.mta.springissuer.model.request.CredentialRequest;

import java.util.Map;

// Interface extins care include și encodarea
public interface CredentialIssuanceStrategy {
    Object createCredential(Map<String, Object> userDetails, String credentialId);

    String encodeToSdJwt(Map<String, Object> userDetails, String credentialId);
}