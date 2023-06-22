package br.ufg.twssl.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class CertificadoController {

    @PostMapping ("/certificado")
    public ResponseEntity importaCertificado(){
        return new ResponseEntity("Tudo ok",HttpStatus.CREATED);
    }

}
