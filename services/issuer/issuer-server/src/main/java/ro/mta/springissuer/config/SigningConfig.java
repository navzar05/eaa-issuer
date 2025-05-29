package ro.mta.springissuer.config;

import com.nimbusds.jose.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

@Configuration
public class SigningConfig {
    @Value("${token.key.alias}")
    private String keyAlias;

    @Value("${token.pin}")
    private String tokenPin;

    @Value("${token.configpath}")
    private String configFilePath;

    @Bean
    public Provider pkcs11Provider() throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        Resource resource = new ClassPathResource("pkcs11.cfg");
        File tempConfigFile = File.createTempFile("pkcs11", ".cfg");
        try (InputStream in = resource.getInputStream(); FileOutputStream out = new FileOutputStream(tempConfigFile)) {
            in.transferTo(out);
        }

        Provider provider = Security.getProvider("SunPKCS11").configure(tempConfigFile.getAbsolutePath());
        Security.addProvider(provider);
        System.out.println("PKCS#11 provider added: " + provider.getName());

        return provider;
    }

    @Bean
    public KeyStore tokenKeyStore(Provider pkcs11Provider) throws Exception {
        try {
            System.out.println("Initializing KeyStore with provider: " + pkcs11Provider.getName());
            System.out.println("Provider info: " + pkcs11Provider.getInfo());

            System.out.println("Provider services:");
            pkcs11Provider.getServices().forEach(service -> {
                System.out.println(" - " + service.getType() + ": " + service.getAlgorithm());
            });

            System.out.println("Available KeyStore types in the system:");
            Security.getAlgorithms("KeyStore").forEach(type -> {
                System.out.println(" - " + type);
            });

            char[] pin = tokenPin.toCharArray();

            try {
                System.out.println("Attempting to create KeyStore with type 'PKCS11'");
                KeyStore ks = KeyStore.getInstance("PKCS11", pkcs11Provider);
                System.out.println("KeyStore created successfully, loading it...");
                ks.load(null, pin);
                System.out.println("KeyStore loaded successfully!");
                return ks;
            } catch (Exception e) {
                System.out.println("Error creating/loading KeyStore: " + e.getClass().getName() + ": " + e.getMessage());
                e.printStackTrace();

                System.out.println("Trying alternative approach without specifying provider...");
                try {
                    KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", null,
                            new KeyStore.PasswordProtection(pin));
                    KeyStore ks = builder.getKeyStore();
                    System.out.println("Alternative approach succeeded!");
                    return ks;
                } catch (Exception e2) {
                    System.out.println("Alternative approach failed: " + e2.getMessage());
                    throw e;
                }
            }
        } catch (Exception e) {
            System.err.println("Fatal error initializing KeyStore: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Bean
    public PrivateKey signingKey(KeyStore tokenKeyStore) {
        try {
            Key key = tokenKeyStore.getKey(keyAlias, null);
            if (key instanceof PrivateKey) {
                return (PrivateKey) key;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Bean
    public List<Base64> signingCertificateChain(KeyStore tokenKeyStore) throws Exception {
        Certificate cert = tokenKeyStore.getCertificate(keyAlias);
        List<Base64> chain = new ArrayList<>();
        chain.add(Base64.encode(cert.getEncoded()));
        return chain;
    }

    @Bean
    public Signature tokenSignature(Provider pkcs11Provider, PrivateKey signingKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA", pkcs11Provider);
        signature.initSign(signingKey);
        return signature;
    }
}