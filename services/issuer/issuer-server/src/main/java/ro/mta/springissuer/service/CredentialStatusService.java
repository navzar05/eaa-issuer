package ro.mta.springissuer.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class CredentialStatusService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String ID_KEY = "credential_id";

    public CredentialStatusService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    private Long generateNextId() {
        return redisTemplate.opsForValue().increment(ID_KEY);
    }

    private void initializeSequence() {
        if (!redisTemplate.hasKey(ID_KEY)) {
            redisTemplate.opsForValue().set(ID_KEY, 0);
        }
    }

    // Create new credential status with auto-generated ID
    public Long createCredentialStatus(Boolean status) {
        initializeSequence();
        Long newId = generateNextId();
        String key = String.valueOf(newId);
        redisTemplate.opsForValue().set(key, status);
        return newId;
    }

    // Save or update credential status (for existing IDs)
    public void saveCredentialStatus(Long credentialId, Boolean status) {
        String key = String.valueOf(credentialId);
        Integer value = status ? 1 : 0;
        redisTemplate.opsForValue().set(key, value);
    }

    // Get credential status by ID
    public Optional<Boolean> getCredentialStatus(Long credentialId) {
        String key = String.valueOf(credentialId);
        Object value = redisTemplate.opsForValue().get(key);
        if (value != null) {
            Integer intValue = (Integer) value;
            return Optional.of(intValue == 1);
        }
        return Optional.empty();
    }

    // Update credential status
    public boolean updateCredentialStatus(Long credentialId, Boolean status) {
        String key = String.valueOf(credentialId);
        if (redisTemplate.hasKey(key)) {
            Integer value = status ? 1 : 0;
            redisTemplate.opsForValue().set(key, value);
            return true;
        }
        return false;
    }

    // Delete credential status
    public boolean deleteCredentialStatus(Long credentialId) {
        String key = String.valueOf(credentialId);
        return redisTemplate.delete(key);
    }

    // Get all credentials as Map<credentialId, status>
    public Map<Long, Boolean> getAllCredentialStatuses() {
        // Get all numeric keys (exclude the sequence key)
        Set<String> allKeys = redisTemplate.keys("*");
        if (allKeys.isEmpty()) {
            return new HashMap<>();
        }

        Map<Long, Boolean> credentials = new HashMap<>();
        for (String key : allKeys) {
            // Skip the sequence key and only process numeric keys
            if (key.equals(ID_KEY)) {
                continue;
            }

            try {
                Long credentialId = Long.parseLong(key);
                Object value = redisTemplate.opsForValue().get(key);
                if (value != null) {
                    Integer intValue = (Integer) value;
                    credentials.put(credentialId, intValue == 1);
                }
            } catch (NumberFormatException e) {
                // Skip non-numeric keys
            }
        }
        return credentials;
    }

    // Get credentials filtered by status
    public Map<Long, Boolean> getCredentialsByStatus(Boolean status) {
        return getAllCredentialStatuses().entrySet().stream()
                .filter(entry -> entry.getValue().equals(status))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    // Check if credential exists
    public boolean existsCredential(Long credentialId) {
        String key = String.valueOf(credentialId);
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    // Get all credential IDs
    public Set<Long> getAllCredentialIds() {
        Set<String> allKeys = redisTemplate.keys("*");
        if (allKeys == null || allKeys.isEmpty()) {
            return new HashSet<>();
        }

        return allKeys.stream()
                .filter(key -> !key.equals(ID_KEY)) // Exclude sequence key
                .map(key -> {
                    try {
                        return Long.parseLong(key);
                    } catch (NumberFormatException e) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    // Get count of credentials by status
    public long countCredentialsByStatus(Boolean status) {
        return getAllCredentialStatuses().values().stream()
                .mapToLong(s -> s.equals(status) ? 1 : 0)
                .sum();
    }

    // Get current ID sequence value
    public Long getCurrentIdSequence() {
        Object value = redisTemplate.opsForValue().get(ID_KEY);
        return value != null ? Long.valueOf(value.toString()) : 0L;
    }

    // Bulk operations
    public void saveMultipleCredentials(Map<Long, Boolean> credentials) {
        Map<String, Object> keyValueMap = credentials.entrySet().stream()
                .collect(Collectors.toMap(
                        entry -> String.valueOf(entry.getKey()),
                        entry -> entry.getValue() ? 1 : 0
                ));
        redisTemplate.opsForValue().multiSet(keyValueMap);
    }

    // Get multiple credentials at once
    public Map<Long, Boolean> getMultipleCredentials(Set<Long> credentialIds) {
        if (credentialIds == null || credentialIds.isEmpty()) {
            return new HashMap<>();
        }

        List<String> keys = credentialIds.stream()
                .map(String::valueOf)
                .collect(Collectors.toList());

        List<Object> values = redisTemplate.opsForValue().multiGet(keys);
        Map<Long, Boolean> result = new HashMap<>();

        for (int i = 0; i < keys.size(); i++) {
            if (values.get(i) != null) {
                Long credentialId = Long.parseLong(keys.get(i));
                Integer intValue = (Integer) values.get(i);
                result.put(credentialId, intValue == 1);
            }
        }
        return result;
    }

    // Get credentials in the exact format you want: "id:status"
    public List<String> getCredentialsAsStringList() {
        Map<Long, Boolean> credentials = getAllCredentialStatuses();
        return credentials.entrySet().stream()
                .sorted(Map.Entry.comparingByKey()) // Sort by ID
                .map(entry -> entry.getKey() + ":" + (entry.getValue() ? 1 : 0))
                .collect(Collectors.toList());
    }

    // Get credentials as a simple string format
    public String getCredentialsAsString() {
        return String.join(", ", getCredentialsAsStringList());
    }
}
