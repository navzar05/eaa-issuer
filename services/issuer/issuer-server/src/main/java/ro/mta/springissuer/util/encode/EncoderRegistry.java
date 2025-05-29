package ro.mta.springissuer.util.encode;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Component
public class EncoderRegistry {

    private final Map<String, Encoder> encoders = new HashMap<>();

    public void register(String vct, Encoder encoder) {
        encoders.put(vct, encoder);
    }


    public Encoder getEncoder(String vct) {
        Encoder encoder = encoders.get(vct);
        if (encoder == null) {
            throw new IllegalArgumentException("No encoder registered for credential type: " + vct);
        }
        return encoder;
    }


    public boolean supportsCredentialType(String vct) {
        return encoders.containsKey(vct);
    }


    public Set<String> getRegisteredVcts() {
        return encoders.keySet();
    }


    public void unregister(String vct) {
        encoders.remove(vct);
    }
}
