package ro.mta.springissuer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ro.mta.springissuer.util.encode.EncoderRegistry;
import ro.mta.springissuer.util.encode.graduation.UnivGradSdJwtEncoder;
import ro.mta.springissuer.util.encode.pid.PidSdJwtEncoder;

@Configuration
public class EncoderRegistryConfig {

    @Bean
    public EncoderRegistry encoderRegistry(PidSdJwtEncoder pidSdJwtEncoder,
                                           UnivGradSdJwtEncoder univGradSdJwtEncoder) {

        EncoderRegistry encoderRegistry = new EncoderRegistry();
        encoderRegistry.registerEncoder("urn:eu.europa.ec.eudi:pid:1", pidSdJwtEncoder);
        encoderRegistry.registerEncoder("urn:org:certsign:university:graduation:1", univGradSdJwtEncoder);
        return encoderRegistry;
    }
}
