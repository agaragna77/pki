//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.client;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JSSTrustManager for PKI HTTP clients.
 *
 * <p>Loads trust anchors from the NSS certificate database (internal token)
 * only. The default {@link JSSTrustManager} uses {@link CryptoManager#getCACerts()},
 * which enumerates CA certificates on all PKCS#11 modules and can trigger
 * password prompts on unrelated HSM tokens.
 */
public class ClientJSSTrustManager extends JSSTrustManager {

    private static final Logger logger = LoggerFactory.getLogger(ClientJSSTrustManager.class);

    @Override
    public X509Certificate[] getAcceptedIssuers() {

        logger.debug("ClientJSSTrustManager: getAcceptedIssuers():");

        Collection<X509Certificate> caCerts = new ArrayList<>();

        try {
            CryptoManager manager = CryptoManager.getInstance();
            CryptoToken token = manager.getInternalKeyStorageToken();
            CryptoStore store = token.getCryptoStore();

            for (org.mozilla.jss.crypto.X509Certificate cert : store.getCertificates()) {

                if (!isTrustAnchor(cert)) {
                    continue;
                }

                logger.debug("ClientJSSTrustManager:  - " + cert.getSubjectDN());

                try {
                    PK11Cert caCert = (PK11Cert) cert;
                    caCert.checkValidity();
                    caCerts.add(caCert);

                } catch (Exception e) {
                    logger.debug("ClientJSSTrustManager: " + e.getClass().getName() + ": " + e.getMessage());
                }
            }

        } catch (NotInitializedException e) {
            logger.error("ClientJSSTrustManager: Unable to get CryptoManager: " + e, e);
            throw new RuntimeException(e);
        } catch (Exception e) {
            logger.error("ClientJSSTrustManager: Unable to list trust anchors: " + e, e);
            throw new RuntimeException(e);
        }

        return caCerts.toArray(new X509Certificate[caCerts.size()]);
    }

    private static boolean isTrustAnchor(org.mozilla.jss.crypto.X509Certificate cert) {

        if (!(cert instanceof PK11Cert)) {
            return false;
        }

        return isCATrust(cert.getSSLTrust())
                || isCATrust(cert.getEmailTrust())
                || isCATrust(cert.getObjectSigningTrust());
    }

    private static boolean isCATrust(int trust) {

        return org.mozilla.jss.crypto.X509Certificate.isTrustFlagEnabled(
                org.mozilla.jss.crypto.X509Certificate.TRUSTED_CA, trust)
            || org.mozilla.jss.crypto.X509Certificate.isTrustFlagEnabled(
                org.mozilla.jss.crypto.X509Certificate.TRUSTED_CLIENT_CA, trust)
            || org.mozilla.jss.crypto.X509Certificate.isTrustFlagEnabled(
                org.mozilla.jss.crypto.X509Certificate.VALID_CA, trust)
            || org.mozilla.jss.crypto.X509Certificate.isTrustFlagEnabled(
                org.mozilla.jss.crypto.X509Certificate.NS_TRUSTED_CA, trust);
    }
}
