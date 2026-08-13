//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.client;

import java.io.IOException;

import org.mozilla.jss.crypto.CryptoToken;

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
            String tokenName = configuredTokenName;
            if (tokenName == null || tokenName.isEmpty()) {
                tokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
            }

            CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
            return token.getName() + ":" + nickname;

        } catch (Exception e) {
            throw new IOException("Unable to resolve client certificate nickname: " + e.getMessage(), e);
        }
    }
}
