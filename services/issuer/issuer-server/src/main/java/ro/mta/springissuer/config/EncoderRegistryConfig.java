package ro.mta.springissuer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ro.mta.springissuer.util.encode.EncoderRegistry;
import ro.mta.springissuer.util.credential.graduation.EncodeGraduationInSdJwtVc;
import ro.mta.springissuer.util.credential.pid.EncodePidInSdJwtVc;

@Configuration
public class EncoderRegistryConfig {

    @Bean
    public EncoderRegistry encoderRegistry(
            EncodePidInSdJwtVc pidEncoder,
            EncodeGraduationInSdJwtVc graduationEncoder) {

        EncoderRegistry registry = new EncoderRegistry();

        // Register all encoders
        registry.register("urn:eu.europa.ec.eudi:pid:1", pidEncoder);
        registry.register("urn:org:certsign:university:graduation:1", graduationEncoder);

        return registry;
    }
}