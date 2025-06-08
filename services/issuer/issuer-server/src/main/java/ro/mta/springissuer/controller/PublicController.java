package ro.mta.springissuer.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;

@RestController
@RequestMapping("/public")
public class PublicController {

    Logger log = LoggerFactory.getLogger(PublicController.class);

    @GetMapping("/ic-logo.svg")
    public ResponseEntity<byte[]> getImageAtm() throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("static/atm.svg")) {
            if (in == null) {
                return ResponseEntity.notFound().build();
            }

            byte[] imageBytes = in.readAllBytes();

            return ResponseEntity.ok()
                    .contentType(MediaType.valueOf("image/svg+xml"))
                    .contentLength(imageBytes.length)
                    .body(imageBytes);
        }
    }

    @GetMapping("/package/windows")
    public ResponseEntity<Resource> downloadPackageWindows(){
        try {
            Resource resource = new ClassPathResource("archives/cascade_cli_win.zip");
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/zip"))
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + "cascade_cli_win.zip" + "\"")
                    .body(resource);
        } catch (Exception e) {
            log.error(e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/package/linux")
    public ResponseEntity<Resource> downloadPackageLinux(){
        try {
            Resource resource = new ClassPathResource("archives/cascade_cli_linux.zip");
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/zip"))
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + "cascade_cli_linux.zip" + "\"")
                    .body(resource);
        } catch (Exception e) {
            log.error(e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/token_certificate")
    public ResponseEntity<Resource> downloadTokenCertificate(){
        try {
            Resource resource = new ClassPathResource("certs/token_cert.crt");
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("application/x-pem-file"))
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"token_cert.crt\"")
                    .body(resource);
        } catch (Exception e) {
            log.error(e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }
}
