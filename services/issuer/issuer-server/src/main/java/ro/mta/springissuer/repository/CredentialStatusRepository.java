package ro.mta.springissuer.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import ro.mta.springissuer.entity.CredentialStatus;

import java.util.List;
import java.util.Optional;

@Repository
public interface CredentialStatusRepository extends CrudRepository<CredentialStatus, Long> {

    // Find by status
    List<CredentialStatus> findByStatus(Boolean status);

    // Check if credential exists
    boolean existsByCredentialId(Long credentialId);

    // Custom method to find by credential ID
    Optional<CredentialStatus> findByCredentialId(Long credentialId);
}
