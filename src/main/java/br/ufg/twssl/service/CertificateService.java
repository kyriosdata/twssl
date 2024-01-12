package br.ufg.twssl.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.server.Ssl;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

@Service
public class CertificateService {

    private final Ssl applicationSsl;

    @Autowired
    public CertificateService(final ServerProperties serverProperties){
        this.applicationSsl=serverProperties.getSsl();
    }
    public void addCertificateTruststore(final X509Certificate[] clientCertificates) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, KeyManagementException {
        final KeyStore truststore = this.loadTrustStore();
        // Create a new temporary truststore to hold the updated certificates
        final KeyStore updatedTruststore = KeyStore.getInstance(KeyStore.getDefaultType());
        updatedTruststore.load(null);

        // Load the existing certificates from the default truststore
        final Enumeration<String>aliases = truststore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            updatedTruststore.setCertificateEntry(alias, truststore.getCertificate(alias));
        }

        // Add the client certificates to the temporary truststore
        for (X509Certificate certificate : clientCertificates) {
            updatedTruststore.setCertificateEntry(certificate.getSubjectDN().getName(), certificate);
        }

        // Create a custom TrustManager that uses the temporary truststore
        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(updatedTruststore);
        final X509TrustManager customTrustManager = (X509TrustManager) trustManagerFactory.getTrustManagers()[0];

        // Set the custom TrustManager as the default TrustManager
        final SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{customTrustManager}, null);
        SSLContext.setDefault(sslContext);

        if(!this.isMemoryOnly()){
            // Save the updated truststore
            try (FileOutputStream outputStream = new FileOutputStream(this.applicationSsl.getTrustStore())) {
                updatedTruststore.store(outputStream, this.applicationSsl.getTrustStorePassword().toCharArray());
            }
        }

    }
    public String getCertificateAlias(final X509Certificate clientCertificate) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final KeyStore truststore = this.loadTrustStore();

        // Find the alias corresponding to the given certificate
        Enumeration<String> aliases = truststore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) truststore.getCertificate(alias);
            if (cert.equals(clientCertificate)) {
                return alias;
            }
        }
        return null;
    }

    public boolean isCertificateInTrustStore(final String username) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final KeyStore truststore = this.loadTrustStore();
        return truststore.containsAlias(username);
    }
    public KeyStore loadTrustStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
        if(this.isMemoryOnly()){
            final Resource resource = new ClassPathResource("truststore.jks");
            final InputStream fis = resource.getInputStream();
            truststore.load(fis, this.applicationSsl.getTrustStorePassword().toCharArray());
        }else{
            final FileInputStream fis = new FileInputStream(this.applicationSsl.getTrustStore());
            truststore.load(fis, this.applicationSsl.getTrustStorePassword().toCharArray());
        }
        return truststore;
    }
    public boolean isMemoryOnly(){
        return applicationSsl.getTrustStore().startsWith("classpath:");
    }

}
