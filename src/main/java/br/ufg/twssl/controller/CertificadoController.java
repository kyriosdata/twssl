package br.ufg.twssl.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class CertificadoController {

    @GetMapping ("/certificado")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity importaCertificado(){
        return new ResponseEntity("Tudo ok",HttpStatus.CREATED);
    }

}
