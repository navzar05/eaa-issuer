package ro.mta.springissuer.util.encode.pid;

import com.authlete.sd.Disclosure;
import com.nimbusds.jose.util.Base64;
import org.springframework.stereotype.Component;
import ro.mta.springissuer.model.credential.Credential;
import ro.mta.springissuer.model.credential.Pid;

import ro.mta.springissuer.util.encode.AbstractSdJwtEncoder;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.util.*;

@Component
public class EncodePidInSdJwtVc extends AbstractSdJwtEncoder {

    public EncodePidInSdJwtVc(Provider pkcs11Provider, KeyStore tokenKeyStore,
                              PrivateKey signingKey, List<Base64> signingCertificateChain,
                              Signature tokenSignature) {
        super(pkcs11Provider, tokenKeyStore, signingKey, signingCertificateChain, tokenSignature);
    }

    @Override
    public String encode(Credential credential) {
        if (!(credential instanceof Pid)) {
            throw new IllegalArgumentException("Credential must be of type Pid");
        }
        return createSdJwt(credential, createDisclosures(credential));
    }

    @Override
    protected List<Disclosure> createDisclosures(Credential credential) {
        Pid pid = (Pid) credential;

        return Arrays.asList(
                new Disclosure("family_name", pid.getFamilyName()),
                new Disclosure("given_name", pid.getGivenName()),
                new Disclosure("birthdate", pid.getBirthDate().toString()),
                new Disclosure("is_over_18", pid.getIsOver18()),
                new Disclosure("age_in_years", pid.getAgeInYears()),
                new Disclosure("issuing_authority", "Test PID Issuer"),
                new Disclosure("issuing_country", "RO")
        );
    }
}