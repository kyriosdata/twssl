package br.ufg.twssl.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TokenController {
    @GetMapping("/token")
    public ResponseEntity geraToken(){
        return new ResponseEntity("Tudo ok autenticado", HttpStatus.OK);
    }

    @GetMapping("/autenticado")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity verificaAuth(){
        return new ResponseEntity("Tudo ok autenticado", HttpStatus.OK);
    }
}
