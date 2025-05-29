package ro.mta.springissuer.model.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
public class CredentialRequest {

    @JsonProperty("format")
    private String format;

    @JsonProperty("vct")
    private String vct;


    public void setFormat(String format) {
        this.format = format;
    }

    public void setVct(String vct) {
        this.vct = vct;
    }
}

