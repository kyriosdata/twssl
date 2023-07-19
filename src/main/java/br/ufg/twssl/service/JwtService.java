package br.ufg.twssl.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@AllArgsConstructor
public class JwtService {
    final private CertificateService certificateService;
    @Value("${app.secret-jwt-key}")
    final private static  String SECRECT_KEY="";

    public String extractUsername(final String jwt) {
        return this.extractClaim(jwt,Claims::getSubject);
    }
    private Date extractExpirationDate(String jwt) {
        return this.extractClaim(jwt,Claims::getExpiration);
    }


    public boolean isTokenValid(final String jwt, final UserDetails userDetails){
        final String username=extractUsername(jwt);
        return (username.equals(userDetails.getUsername()) && this.isTokenAlive(jwt));

    }

    private boolean isTokenAlive(final String jwt) {
        return this.extractExpirationDate(jwt).after(new Date(System.currentTimeMillis()));
    }
    public String generateCertificateToken(final X509Certificate[] clientCertificates) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        final String certificateAlias = this.certificateService.getCertificateAlias(clientCertificates[0]);
        if(this.certificateService.isCertificateInTrustStore(certificateAlias)){
            return this.generateToken(certificateAlias);
        }else{
            throw new UsernameNotFoundException("Certificado não cadastrado, favor cadastrar");
        }
    }
    public String generateToken(final String username){
        return Jwts
                .builder()
                .setClaims(new HashMap<>())
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 6))
                .signWith(this.getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(final Map<String, Object> extraClaims, final UserDetails userDetails)
    {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 6))
                .signWith(this.getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    public <T> T extractClaim(final String jwt, Function<Claims,T> claimsResolver){
        final Claims claims = this.extractClaims(jwt);
        return claimsResolver.apply(claims);
    }
    private Claims extractClaims(final String jwt){
        return Jwts
                .parserBuilder()
                .setSigningKey(this.getSigningKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    private Key getSigningKey() {
        final byte[] keyBytes= Decoders.BASE64.decode(SECRECT_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
