package ro.mta.springissuer.controller;

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
}
