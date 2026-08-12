//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.client;

import java.io.IOException;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Cert;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * Resolves unqualified client certificate nicknames to token-qualified
 * nicknames for TLS client authentication.
 */
public class ClientCertNickname {

    private ClientCertNickname() {
    }

    public static String resolve(ClientConfig config) throws IOException {
        if (config == null) {
            return null;
        }

        return resolve(config.getTokenName(), config.getCertNickname());
    }

    public static String resolve(String configuredTokenName, String nickname) throws IOException {
        if (nickname == null) {
            return null;
        }

        if (nickname.contains(":")) {
            return nickname;
        }

        try {
            CryptoManager manager = CryptoManager.getInstance();
            X509Certificate cert = manager.findCertByNickname(nickname);
            if (cert == null) {
                throw new IOException("Certificate not found: " + nickname);
            }

            CryptoToken owningToken;
            if (cert instanceof PK11Cert pk11Cert) {
                owningToken = pk11Cert.getOwningToken();
            } else {
                owningToken = manager.getInternalKeyStorageToken();
            }

            if (configuredTokenName != null && !configuredTokenName.isEmpty()) {
                if (!tokensMatch(configuredTokenName, owningToken)) {
                    throw new IOException(
                            "Configured token '" + configuredTokenName
                            + "' does not match certificate token '"
                            + owningToken.getName() + "' for nickname '" + nickname + "'");
                }
            }

            return owningToken.getName() + ":" + nickname;

        } catch (ObjectNotFoundException e) {
            throw new IOException("Certificate not found: " + nickname, e);

        } catch (IOException e) {
            throw e;

        } catch (Exception e) {
            throw new IOException("Unable to resolve client certificate nickname: " + e.getMessage(), e);
        }
    }

    private static boolean tokensMatch(String configuredTokenName, CryptoToken owningToken)
            throws Exception {

        if (CryptoUtil.isInternalToken(configuredTokenName)) {
            CryptoToken internal = CryptoManager.getInstance().getInternalKeyStorageToken();
            return internal.equals(owningToken);
        }

        CryptoToken configured = CryptoUtil.getKeyStorageToken(configuredTokenName);
        return configured.equals(owningToken);
    }
}
