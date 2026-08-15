//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.client;

import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

import com.netscape.certsrv.client.PKIConnection;

/**
 * Bridges {@link JSSTrustManager} hostname checks to the native
 * {@link SSLCertificateApprovalCallback} used by {@link org.mozilla.jss.ssl.SSLSocket}.
 *
 * <p>Do not call {@link JSSTrustManager#checkCertChain} here: that path walks every
 * visible PKCS#11 token while resolving trust anchors, which reintroduces the
 * DOGTAG-4580 HSM password prompts. NSS already validates the server chain before
 * invoking this callback; the user callback handles remaining validity reasons.
 */
public final class ClientSSLApprovalCallback implements SSLCertificateApprovalCallback {

    private static final org.slf4j.Logger logger =
            org.slf4j.LoggerFactory.getLogger(ClientSSLApprovalCallback.class);

    private final JSSTrustManager trustManager;
    private final SSLCertificateApprovalCallback userCallback;

    private ClientSSLApprovalCallback(
            JSSTrustManager trustManager,
            SSLCertificateApprovalCallback userCallback) {
        this.trustManager = trustManager;
        this.userCallback = userCallback;
    }

    public static SSLCertificateApprovalCallback create(PKIConnection connection, String hostname) {
        JSSTrustManager trustManager = new JSSTrustManager();
        trustManager.setHostname(hostname);
        trustManager.setEnableCertRevokeVerify(connection.getConfig().isCertRevocationVerify());
        return new ClientSSLApprovalCallback(trustManager, connection.getCallback());
    }

    @Override
    public boolean approve(X509Certificate cert, SSLCertificateApprovalCallback.ValidityStatus status) {
        try {
            X509Certificate[] chain = new X509Certificate[] { cert };
            trustManager.checkHostname(chain, status);
        } catch (Exception e) {
            logger.debug("Hostname verification failed: {}", e.getMessage());
            return false;
        }

        if (userCallback != null) {
            return userCallback.approve(cert, status);
        }

        return !hasReasons(status);
    }

    private static boolean hasReasons(SSLCertificateApprovalCallback.ValidityStatus status) {
        Enumeration<?> reasons = status.getReasons();
        return reasons != null && reasons.hasMoreElements();
    }
}
