package ro.mta.springissuer.util.credential;

import org.springframework.stereotype.Component;
import ro.mta.springissuer.model.credential.Credential;
import ro.mta.springissuer.model.credential.UniversityGraduation;
import ro.mta.springissuer.util.encode.graduation.EncodeGraduationInSdJwtVc;

import java.util.Map;

@Component
public class UnivGradIssuanceStrategy implements CredentialIssuanceStrategy {
    private final EncodeGraduationInSdJwtVc encoder;

    public UnivGradIssuanceStrategy(EncodeGraduationInSdJwtVc encoder) {
        this.encoder = encoder;
    }

    @Override
    public Credential createCredential(Map<String, Object> userDetails, Long credentialId) {
        return new UniversityGraduation(userDetails, credentialId);
    }

    @Override
    public String encodeToSdJwt(Map<String, Object> userDetails, Long credentialId) {
        Credential credential = createCredential(userDetails, credentialId);
        return encoder.encode(credential);
    }
}
