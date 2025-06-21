package ro.mta.springissuer.entity;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

import java.io.Serializable;

@Setter
@Getter
@RedisHash("credential_status")
public class CredentialStatus implements Serializable {

    // Getters and Setters
    @Id
    private Long credentialId;

    @Indexed
    private Boolean status;

    // Constructors
    public CredentialStatus() {}

    public CredentialStatus(Long credentialId, Boolean status) {
        this.credentialId = credentialId;
        this.status = status;
    }

    @Override
    public String toString() {
        return "CredentialStatus{" +
                "credentialId=" + credentialId +
                ", status=" + status +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CredentialStatus that = (CredentialStatus) o;
        return credentialId != null ? credentialId.equals(that.credentialId) : that.credentialId == null;
    }

    @Override
    public int hashCode() {
        return credentialId != null ? credentialId.hashCode() : 0;
    }
}