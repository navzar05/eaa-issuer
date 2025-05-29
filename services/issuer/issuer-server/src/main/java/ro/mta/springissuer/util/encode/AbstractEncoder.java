package ro.mta.springissuer.util.encode;

import com.nimbusds.jose.util.Base64;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ro.mta.springissuer.model.credential.Credential;

import java.security.*;
import java.util.List;

@Getter
@Component
public abstract class AbstractEncoder implements Encoder {

    private static final Logger logger = LoggerFactory.getLogger(AbstractEncoder.class);

    @Value("${server.issuer-url}")
    private String credentialIssuerId;
    @Value("${token.enabled:false}")
    private boolean tokenEnabled;
    private final Provider pkcs11Provider;
    private final KeyStore tokenKeyStore;
    private final PrivateKey signingKey;
    private final List<Base64> signingCertificateChain;
    private final Signature tokenSignature;

    @Autowired
    public AbstractEncoder(
            Provider pkcs11Provider,
            KeyStore tokenKeyStore,
            PrivateKey signingKey,
            List<Base64> signingCertificateChain,
            Signature tokenSignature) {
        this.pkcs11Provider = pkcs11Provider;
        this.tokenKeyStore = tokenKeyStore;
        this.signingKey = signingKey;
        this.signingCertificateChain = signingCertificateChain;
        this.tokenSignature = tokenSignature;
    }


    public abstract String encode(Credential credential);
}
