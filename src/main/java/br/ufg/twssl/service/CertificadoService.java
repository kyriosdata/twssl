package br.ufg.twssl.service;

import br.ufg.twssl.util.TrustStoreUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.server.Ssl;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Service
public class CertificadoService {

    private final Ssl applicationSsl;

    @Autowired
    public CertificadoService(final ServerProperties serverProperties){
        this.applicationSsl=serverProperties.getSsl();
    }

    public void addCertificateKeystore(final X509Certificate[] clientCertificates) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyManagementException {
       this.reloadTrustStoreContext(TrustStoreUtil.addCertificateTruststore(clientCertificates, this.applicationSsl.getTrustStore(), this.applicationSsl.getTrustStorePassword()));
    }

    public void reloadTrustStoreContext(final KeyStore truststore) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        TrustStoreUtil.reloadTrustStore(truststore);
    }

    public boolean isCertificateInTrustStore(final String alias) {
        try {
            return TrustStoreUtil.isCertificateInTruststore(alias, this.applicationSsl.getTrustStore(), this.applicationSsl.getTrustStorePassword());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
