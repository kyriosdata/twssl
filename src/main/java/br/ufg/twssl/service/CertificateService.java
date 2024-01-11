package br.ufg.twssl.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.server.Ssl;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
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
    public void addCertificateKeystore(final X509Certificate[] clientCertificates) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, KeyManagementException {

        // Load the default truststore (change the path if needed)
        final KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
        final FileInputStream fis = new FileInputStream(this.applicationSsl.getTrustStore());
        truststore.load(fis, this.applicationSsl.getTrustStorePassword().toCharArray());

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

        // Save the updated truststore
        try (FileOutputStream outputStream = new FileOutputStream(this.applicationSsl.getTrustStore())) {
            updatedTruststore.store(outputStream, this.applicationSsl.getTrustStorePassword().toCharArray());
        }
    }
    public String getCertificateAlias(final X509Certificate clientCertificate) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String result=null;
        // Load the truststore (change the path and type if needed)
        final KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
        final FileInputStream fis = new FileInputStream(this.applicationSsl.getTrustStore());
        truststore.load(fis, this.applicationSsl.getTrustStorePassword().toCharArray());

        // Find the alias corresponding to the given certificate
        Enumeration<String> aliases = truststore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) truststore.getCertificate(alias);
            if (cert.equals(clientCertificate)) {
                result=alias;
            }else{
                result=null;
            }
        }
        return result; // Certificate alias not found in the truststore
    }

    public boolean isCertificateInTrustStore(final String username) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        // Load the truststore
        final KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
        final FileInputStream fis = new FileInputStream(this.applicationSsl.getTrustStore());
        truststore.load(fis, this.applicationSsl.getTrustStorePassword().toCharArray());

        // Check if the alias exists in the truststore
        return truststore.containsAlias(username);
    }

}
