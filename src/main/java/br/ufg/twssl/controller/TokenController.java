package br.ufg.twssl.controller;

import br.ufg.twssl.service.CertificateService;
import br.ufg.twssl.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class TokenController {
    private final JwtService jwtService;
    @GetMapping("/token")
    public ResponseEntity geraToken(HttpServletRequest request) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        final X509Certificate[] clientCertificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        return new ResponseEntity(this.jwtService.generateCertificateToken(clientCertificates), HttpStatus.OK);
    }

    @GetMapping("/autenticado")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity verificaAuth(){
        return new ResponseEntity("Tudo ok autenticado", HttpStatus.OK);
    }
}
