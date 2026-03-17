//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra;

import org.dogtagpki.legacy.kra.KRAPolicyConfig;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.kra.KeyRecoveryAuthority;

public class KRAConfig extends ConfigStore {

    public KRAConfig(ConfigStorage storage) {
        super(storage);
    }

    public KRAConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns kra.Policy.* parameters.
     */
    public KRAPolicyConfig getPolicyConfig() {
        return getSubStore(KeyRecoveryAuthority.PROP_POLICY, KRAPolicyConfig.class);
    }

    /** Config key for key storage strategy: "wrapped" (default) or "seed" */
    public static final String PROP_KEY_STORAGE_STRATEGY = "keyStorageStrategy";
    public static final String KEY_STORAGE_STRATEGY_WRAPPED = "wrapped";
    public static final String KEY_STORAGE_STRATEGY_SEED = "seed";

    /**
     * Returns key storage strategy for archived keys: "wrapped" (store wrapped key material)
     * or "seed" (store seed, derive key on recovery). Default is "wrapped".
     */
    public String getKeyStorageStrategy() {
        return getString(PROP_KEY_STORAGE_STRATEGY, KEY_STORAGE_STRATEGY_WRAPPED);
    }
}
