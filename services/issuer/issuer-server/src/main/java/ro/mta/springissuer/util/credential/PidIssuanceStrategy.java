package ro.mta.springissuer.util.credential;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import ro.mta.springissuer.model.credential.Credential;
import ro.mta.springissuer.model.credential.Pid;
import ro.mta.springissuer.model.request.CredentialRequest;
import ro.mta.springissuer.util.encode.pid.EncodePidInSdJwtVc;

import java.util.Map;

@Component
public class PidIssuanceStrategy implements CredentialIssuanceStrategy {
    private final EncodePidInSdJwtVc encoder;

    public PidIssuanceStrategy(EncodePidInSdJwtVc encoder) {
        this.encoder = encoder;
    }

    @Override
    public Credential createCredential(Map<String, Object> userDetails, String credentialId) {
        return new Pid(userDetails, credentialId);
    }

    @Override
    public String encodeToSdJwt(Map<String, Object> userDetails, String credentialId) {
        Credential credential = createCredential(userDetails, credentialId);
        return encoder.encode(credential);
    }
}