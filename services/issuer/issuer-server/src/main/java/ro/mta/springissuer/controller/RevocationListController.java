package ro.mta.springissuer.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import ro.mta.springissuer.service.RevocationListService;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

@RestController
public class RevocationListController {

    private static final Logger logger = LoggerFactory.getLogger(RevocationListController.class);

    private final RevocationListService revocationListService;

    RevocationListController(RevocationListService revocationListService) {
        this.revocationListService = revocationListService;
    }

    @GetMapping("/revocation-list")
    public ResponseEntity<Map<String, String>> getStatusList() {
        try {
            String content = Files.readString(Paths.get(revocationListService.getStatusListPath()));
            Map<String, String> response = Map.of("jwt", content);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (IOException e) {
            logger.error("Error reading status list file: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
