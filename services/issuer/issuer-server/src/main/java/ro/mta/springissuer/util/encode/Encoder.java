package ro.mta.springissuer.util.encode;

import ro.mta.springissuer.model.credential.Credential;

public interface Encoder {
    String encode(Credential credential);
}
