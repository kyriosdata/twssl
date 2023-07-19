package br.ufg.twssl.controller;

import br.ufg.twssl.service.CertificateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;

@RestController
@RequestMapping("/certificado")
public class CertificadoController {

    @Autowired
    private CertificateService certificateService;

    @PostMapping()
    public ResponseEntity insereCertificado(HttpServletRequest request){
         {
            try {
                X509Certificate[] clientCertificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
                this.certificateService.addCertificateKeystore(clientCertificates);

                return ResponseEntity.ok("Certificate added successfully to the truststore.");
            } catch (Exception e) {
                e.printStackTrace();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to add certificate to the truststore.");
            }
        }
    }
}
