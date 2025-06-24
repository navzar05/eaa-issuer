package ro.mta.springissuer.util.encode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class EncoderRegistry {
    Logger LOG = LoggerFactory.getLogger(EncoderRegistry.class);



    private final Map<String, AbstractSdJwtEncoder> encoders = new HashMap<>();

    public void registerEncoder(final String vct, final AbstractSdJwtEncoder encoder) {
        this.encoders.put(vct, encoder);
    }

    public AbstractSdJwtEncoder getEncoder(final String vct) {
        AbstractSdJwtEncoder encoder = this.encoders.get(vct);

        if (encoder == null) {
            LOG.warn("No encoder registered for {}", vct);
            throw new RuntimeException("No encoder registered for " + vct);
        }

        return encoder;
    }

    public boolean containsEncoder(final String vct) {
        return this.encoders.containsKey(vct);
    }
}
