package ro.mta.springissuer.config;

import com.nimbusds.jose.util.Base64;
import lombok.extern.java.Log;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
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
    public KeyStore tokenKeyStore(Provider pkcs11Provider) throws Exception {
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
                logger.error("Error creating/loading KeyStore: {}: {}", e.getClass().getName(), e.getMessage());
                throw e;
            }
        } catch (Exception e) {
            logger.error("Fatal error initializing KeyStore: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Obține o referința cheia privată din KeyStore pentru semnarea atestărilor.
     * Cheia nu este exportată.
     * @param tokenKeyStore KeyStore-ul de pe token USB
     * @return Cheia privată pentru semnare sau null dacă nu se găsește
     */
    @Bean
    public PrivateKey signingKey(KeyStore tokenKeyStore) {
        try {
            Key key = tokenKeyStore.getKey(keyAlias, null);
            if (key instanceof PrivateKey) {
                return (PrivateKey) key;
            }
        } catch (Exception e) {
            logger.error("Fatal error initializing PrivateKey: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Construiește lanțul de certificate pentru validarea semnăturii.
     *
     * @param tokenKeyStore KeyStore-ul de pe token USB
     * @return Lista cu certificatele encodate în Base64
     * @throws Exception dacă extragerea certificatului eșuează
     */
    @Bean
    public List<Base64> signingCertificateChain(KeyStore tokenKeyStore) throws Exception {
        Certificate cert = tokenKeyStore.getCertificate(keyAlias);
        List<Base64> chain = new ArrayList<>();
        chain.add(Base64.encode(cert.getEncoded()));
        return chain;
    }

    /**
     * Inițializează obiectul Signature pentru semnarea documentelor cu algoritm ECDSA.
     *
     * @param pkcs11Provider Provider-ul PKCS#11 pentru operațiile criptografice
     * @param signingKey Cheia privată pentru semnare
     * @return Obiectul Signature inițializat și pregătit pentru semnare
     * @throws Exception dacă inițializarea semnăturii eșuează
     */
    @Bean
    public Signature tokenSignature(Provider pkcs11Provider, PrivateKey signingKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA", pkcs11Provider);
        signature.initSign(signingKey);
        return signature;
    }
}