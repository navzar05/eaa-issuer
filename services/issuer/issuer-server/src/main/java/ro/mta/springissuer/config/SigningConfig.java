package ro.mta.springissuer.config;

import com.nimbusds.jose.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Clasă de configurare pentru Token USB.
 */
@Configuration
public class SigningConfig {

    Logger logger = LoggerFactory.getLogger(SigningConfig.class);

    @Value("${token.key.alias}")
    private String keyAlias;

    @Value("${token.pin}")
    private String tokenPin;

    @Value("${token.library.path:/usr/lib/libeTPkcs11.so}")
    private String libraryPath;

    @Value("${token.slot.id:0}")
    private String slotId;

    private KeyPair generatedKeyPair;
    private boolean usingGeneratedKey = false;

    /**
     * Configurează și înregistrează provider-ul PKCS#11 pentru token USB.
     * Adaugă și BouncyCastle provider pentru algoritmi criptografici suplimentari.
     *
     * @return Provider-ul PKCS#11 configurat
     * @throws IOException dacă configurarea provider-ului eșuează
     */
    @Bean
    public Provider pkcs11Provider() throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        Provider provider = Security.getProvider("SunPKCS11").configure("--" + String.format("""
            name = SafeNet
            library = %s
            slot = %s
            """, libraryPath, slotId));

        Security.addProvider(provider);
        logger.debug("PKCS#11 provider added: {}", provider.getName());

        return provider;
    }

    /**
     * Inițializează și încarcă KeyStore-ul de pe token USB.
     *
     * @param pkcs11Provider Provider-ul PKCS#11 configurat
     * @return KeyStore-ul încărcat cu certificatele și cheile de pe token
     * @throws Exception dacă inițializarea KeyStore-ului eșuează
     */
    @Bean
    public KeyStore tokenKeyStore(Provider pkcs11Provider) {
        try {
            logger.debug("Initializing KeyStore with provider: {}", pkcs11Provider.getName());
            logger.debug("Provider info: {}", pkcs11Provider.getInfo());

            logger.debug("Provider services:");
            pkcs11Provider.getServices().forEach(service -> {
                logger.debug(" - {}: {}", service.getType(), service.getAlgorithm());
            });

            logger.debug("Available KeyStore types in the system:");
            Security.getAlgorithms("KeyStore").forEach(type -> {
                logger.debug(" - {}", type);
            });

            char[] pin = tokenPin.toCharArray();

            try {
                logger.debug("Attempting to create KeyStore with type 'PKCS11'");
                KeyStore ks = KeyStore.getInstance("PKCS11", pkcs11Provider);
                logger.debug("KeyStore created successfully, loading it...");
                ks.load(null, pin);
                logger.debug("KeyStore loaded successfully!");
                return ks;
            } catch (Exception e) {
                logger.warn("Token KeyStore not available: {}: {}. Will use runtime key generation.",
                        e.getClass().getSimpleName(), e.getMessage());
                return createFallbackKeyStore();
            }
        } catch (Exception e) {
            logger.warn("PKCS#11 provider not available: {}. Will use runtime key generation.", e.getMessage());
            return createFallbackKeyStore();
        }
    }

    /**
     * Creează un KeyStore în memorie gol ca fallback când token-ul nu este disponibil.
     *
     * @return KeyStore gol în memorie
     */
    private KeyStore createFallbackKeyStore() {
        try {
            KeyStore fallbackKs = KeyStore.getInstance("JKS");
            fallbackKs.load(null, null); // Initialize empty keystore
            logger.info("Created fallback in-memory KeyStore");
            return fallbackKs;
        } catch (Exception e) {
            logger.error("Failed to create fallback KeyStore: {}", e.getMessage());
            throw new RuntimeException("Cannot create fallback KeyStore", e);
        }
    }


    /**
     * Obține o referința cheia privată din KeyStore pentru semnarea atestărilor.
     * Dacă cheia nu există pe token, generează o pereche de chei ECDSA la runtime.
     * Cheia generată nu este salvată nicăieri.
     *
     * @param tokenKeyStore KeyStore-ul de pe token USB
     * @return Cheia privată pentru semnare
     */
    @Bean
    public PrivateKey signingKey(KeyStore tokenKeyStore) {
        try {
            Key key = tokenKeyStore.getKey(keyAlias, null);
            if (key instanceof PrivateKey) {
                logger.info("Using private key from token with alias: {}", keyAlias);
                usingGeneratedKey = false;
                return (PrivateKey) key;
            }
        } catch (Exception e) {
            logger.warn("Could not retrieve key from token: {}", e.getMessage());
        }

        try {
            logger.info("Key not found on token. Generating new ECDSA key pair at runtime (P-256 curve)");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256); // P-256 curve
            generatedKeyPair = keyGen.generateKeyPair();
            usingGeneratedKey = true;

            logger.info("Successfully generated ECDSA key pair. Key will not be persisted.");
            return generatedKeyPair.getPrivate();
        } catch (Exception e) {
            logger.error("Fatal error generating key pair: {}", e.getMessage());
            throw new RuntimeException("Could not generate key pair", e);
        }
    }

    /**
     * Construiește lanțul de certificate pentru validarea semnăturii.
     * Dacă se folosește o cheie generată la runtime, creează un certificat self-signed.
     *
     * @param tokenKeyStore KeyStore-ul de pe token USB
     * @return Lista cu certificatele encodate în Base64
     * @throws Exception dacă extragerea/generarea certificatului eșuează
     */
    @Bean
    public List<Base64> signingCertificateChain(KeyStore tokenKeyStore) throws Exception {
        List<Base64> chain = new ArrayList<>();

        if (!usingGeneratedKey) {
            // Use certificate from token
            Certificate cert = tokenKeyStore.getCertificate(keyAlias);
            if (cert != null) {
                chain.add(Base64.encode(cert.getEncoded()));
                logger.info("Using certificate from token");
            } else {
                logger.warn("No certificate found on token for alias: {}", keyAlias);
                throw new RuntimeException("No certificate found on token for alias: " + keyAlias);
            }
        } else {
            // Create self-signed certificate for generated key
            X509Certificate selfSignedCert = createSelfSignedCertificate(generatedKeyPair);
            chain.add(Base64.encode(selfSignedCert.getEncoded()));
            logger.info("Created self-signed certificate for generated key");
        }

        return chain;
    }

    /**
     * Creează un certificat self-signed pentru o pereche de chei generată.
     *
     * @param keyPair Perechea de chei pentru care se creează certificatul
     * @return Certificatul X509 self-signed
     * @throws Exception dacă crearea certificatului eșuează
     */
    private X509Certificate createSelfSignedCertificate(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=Generated Key, O=Spring Issuer, C=RO");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        Date notBefore = new Date();
        Date notAfter = Date.from(LocalDateTime.now().plusYears(1).atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                serial,
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);
    }

    /**
     * Inițializează obiectul Signature pentru semnarea documentelor cu algoritm ECDSA.
     * Folosește provider-ul PKCS#11 pentru chei de pe token sau provider-ul standard pentru chei generate.
     *
     * @param pkcs11Provider Provider-ul PKCS#11 pentru operațiile criptografice
     * @param signingKey Cheia privată pentru semnare
     * @return Obiectul Signature inițializat și pregătit pentru semnare
     * @throws Exception dacă inițializarea semnăturii eșuează
     */
    @Bean
    public Signature tokenSignature(Provider pkcs11Provider, PrivateKey signingKey) throws Exception {
        Signature signature;

        if (usingGeneratedKey) {
            // Use standard provider for generated keys
            signature = Signature.getInstance("SHA256withECDSA");
            logger.info("Using standard provider for generated key signature");
        } else {
            // Use PKCS#11 provider for token keys
            signature = Signature.getInstance("SHA256withECDSA", pkcs11Provider);
            logger.info("Using PKCS#11 provider for token key signature");
        }

        signature.initSign(signingKey);
        return signature;
    }
}