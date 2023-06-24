package br.ufg.twssl.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class CertificadoController {

    @PutMapping ("/certificado")
    public ResponseEntity importaCertificado(){
        return new ResponseEntity("Tudo ok certificado",HttpStatus.CREATED);
    }

    @GetMapping ("/token")
    public ResponseEntity getToken(){
        return new ResponseEntity("Tudo ok token",HttpStatus.OK);
    }

    @GetMapping("/autenticado")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity verificaAuth(){
        return new ResponseEntity("Tudo ok autenticado", HttpStatus.OK);
    }
}
