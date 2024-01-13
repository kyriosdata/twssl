package br.ufg.twssl.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Service
@AllArgsConstructor
public class JwtService {
    final private CertificateService certificateService;

    public String extractUsername(final String jwt) {
        return this.extractClaim(jwt, Claims::getSubject);
    }

    private Date extractExpirationDate(String jwt) {
        return this.extractClaim(jwt, Claims::getExpiration);
    }


    public boolean isTokenValid(final String jwt, final UserDetails userDetails) {
        final String username = extractUsername(jwt);
        return (username.equals(userDetails.getUsername()) && this.isTokenAlive(jwt));

    }

    private boolean isTokenAlive(final String jwt) {
        return this.extractExpirationDate(jwt).after(new Date(System.currentTimeMillis()));
    }

    public String generateCertificateToken(final X509Certificate[] clientCertificates) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        final String certificateAlias = this.certificateService.getCertificateAlias(clientCertificates[0]);
        try {
            return this.generateToken(certificateAlias, this.certificateService.generateKeyPair().getPrivate());
        } catch (Exception e) {
            throw new UsernameNotFoundException("Certificado não cadastrado, favor cadastrar");
        }
    }

    public String generateToken(final String subject, PrivateKey privateKey) {
        return Jwts
                .builder()
                .setClaims(new HashMap<>())
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 180))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public <T> T extractClaim(final String jwt, Function<Claims, T> claimsResolver) {
        final Claims claims = this.extractClaims(jwt);
        return claimsResolver.apply(claims);
    }

    private Claims extractClaims(final String jwt) {
        return Jwts
                .parserBuilder()
                .setSigningKey(this.getPublicKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    private Key getPublicKey() {
        final KeyStore keyStore;
        final Certificate certificate;
        try {
            keyStore = this.certificateService.loadKeyStore();
            certificate = keyStore.getCertificate("localhost");
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return certificate.getPublicKey();
    }
}
