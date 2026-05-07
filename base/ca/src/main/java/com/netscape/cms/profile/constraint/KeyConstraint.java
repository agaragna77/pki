// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.constraint;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.Vector;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.provider.DSAPublicKey;
import org.mozilla.jss.netscape.security.provider.RSAPublicKey;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.common.PolicyConstraintConfig;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.PolicyDefault;
import com.netscape.cms.profile.def.UserKeyDefault;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This constraint is to check the key type and
 * key length.
 *
 * @version $Revision$, $Date$
 */

public class KeyConstraint extends EnrollConstraint {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeyConstraint.class);

    public static final String CONFIG_KEY_TYPE = "keyType"; // (EC, RSA, MLDSA)
    public static final String CONFIG_KEY_PARAMETERS = "keyParameters";
    private static final String CONFIG_ALLOWED_KEYS_PARAM = "allowedKeys";
    private static final String CONFIG_ALLOWED_KEYS_PREFIX = CONFIG_ALLOWED_KEYS_PARAM + ".";
    
    private static String[] cfgECCurves = null;
    private static String keyType = "";
    private static String keyParams = "";
    private static String allowedKeys = "";

    public KeyConstraint() {
        super();
        addConfigName(CONFIG_KEY_TYPE);
        addConfigName(CONFIG_KEY_PARAMETERS);
    }

    @Override
    public void init(PolicyConstraintConfig config) throws EProfileException {
        super.init(config);

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        String ecNames = "";
        try {
            ecNames = cs.getString("keys.ecc.curve.list");
        } catch (Exception e) {
            logger.warn("KeyConstraint.init: could not read keys.ecc.curve.list: {}", e.getMessage());
        }

        logger.debug("KeyConstraint.init ecNames: " + ecNames);
        if (ecNames != null && ecNames.length() != 0) {
            cfgECCurves = ecNames.split(",");
        }
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_KEY_TYPE)) {
            return new Descriptor(IDescriptor.CHOICE, "-,RSA,EC,MLDSA",
                    "RSA",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_TYPE"));
        } else if (name.equals(CONFIG_KEY_PARAMETERS)) {
            return new Descriptor(IDescriptor.STRING, null, "",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_PARAMETERS"));
        }

        return null;
    }

    private ConfigStore getAllowedKeysStore() {
        try {
            ConfigStore params = getConfigStore().getSubStore(CONFIG_PARAMS, ConfigStore.class);
            if (params == null) {
                return null;
            }
            return params.getSubStore(CONFIG_ALLOWED_KEYS_PARAM, ConfigStore.class);
        } catch (Exception e) {
            logger.warn("KeyConstraint: could not open constraint.params.allowedKeys: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Reads all {@code allowedKeys.*} leaves into a nested map: algType = prefix before first {@code .}
     * (uppercase), keyValue = remainder after first {@code .}, value = property string (e.g. true/false).
     * Malformed leaves (not exactly two segments, empty segment, or unreadable value) are logged and skipped.
     */
    private Map<String, Map<String, String>> mapAllowedKeys() throws ERejectException {
        Map<String, Map<String, String>> result = new HashMap<>();
        ConfigStore store = getAllowedKeysStore();
        if (store == null) {
            return result;
        }
        try {
            Enumeration<String> en = store.getPropertyNames();
            while (en.hasMoreElements()) {
                String leaf = en.nextElement();
                String[] parts = leaf.split("\\.", 2);
                if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
                    throw new ERejectException(CMS.getUserMessage("CMS_PROFILE_INVALID_CONFIGURATION_PARAM", leaf));
                }
                String algType = parts[0].toUpperCase(Locale.ROOT);
                validateAlgorithmName(algType);
                String keyValue = parts[1];
                String propValue;
                try {
                    propValue = store.getString(leaf);
                } catch (EBaseException e) {
                    logger.warn("KeyConstraint: allowedKeys property \"{}\" ignored: {}", leaf, e.getMessage());
                    continue;
                }
                result.computeIfAbsent(algType, k -> new HashMap<>()).put(keyValue, propValue);
            }
        } catch (Exception e) {
            logger.warn("KeyConstraint: failed to enumerate allowedKeys: {}", e.getMessage());
        }
        return result;
    }

    /**
     * Starts from {@code baseTokens} (trimmed, non-empty, insertion order preserved), then applies
     * {@code allowedKeysMap} for the algorithm family keyed by {@code algName} in uppercase.
     */
    private Set<String> getAllowedKeysForAlgorithm(
            String[] baseTokens,
            Map<String, Map<String, String>> allowedKeysMap,
            String algName) {
        Set<String> allowed = new LinkedHashSet<>();
        if (baseTokens != null) {
            for (String baseToken : baseTokens) {
                if (baseToken == null) {
                    continue;
                }
                String trimmedToken = baseToken.trim();
                if (!trimmedToken.isEmpty()) {
                    allowed.add(trimmedToken);
                }
            }
        }
        if (algName == null || allowedKeysMap == null) {
            return allowed;
        }
        String algType = algName.toUpperCase();
        Map<String, String> overridesByInnerKey = allowedKeysMap.get(algType);
        if (overridesByInnerKey == null || overridesByInnerKey.isEmpty()) {
            return allowed;
        }
        for (Map.Entry<String, String> entry : overridesByInnerKey.entrySet()) {
            String keyValue = entry.getKey();
            String propertyValue = entry.getValue();
            if (Optional.ofNullable(propertyValue)
                    .map(String::trim)
                    .filter("true"::equalsIgnoreCase)
                    .isPresent()) {
                allowed.add(keyValue);
            } else if (Optional.ofNullable(propertyValue)
                    .map(String::trim)
                    .filter("false"::equalsIgnoreCase)
                    .isPresent()) {
                allowed.remove(keyValue);
            } else {
                logger.warn(
                        "KeyConstraint: configuration: allowedKeys {} entry \"{}\" has non-boolean value \"{}\"; ignored",
                        algType,
                        keyValue,
                        propertyValue);
            }
        }
        return allowed;
    }

    private void checkAllowedAlgorithm(
        int keySize,
        String value,
        String[] baseTokens,
        Map<String, Map<String, String>> allowedKeysMap,
        String algName,
        Request request
    ) throws ERejectException {
        Set<String> allowedKeys = getAllowedKeysForAlgorithm(baseTokens, allowedKeysMap, algName);
        logger.info("{} KeySize is {} with allowed keys {}", algName, keySize, allowedKeys);
        if (!allowedKeys.contains(Integer.toString(keySize))) {
            throw new ERejectException(
                    CMS.getUserMessage(
                            getLocale(request),
                            "CMS_PROFILE_KEY_PARAMS_NOT_MATCHED",
                            value));
        }
        logger.debug("KeyConstraint.validate: {} key contraints passed.", algName);
    }

    @Override
    public Enumeration<String> getConfigNames() {
        Vector<String> names = new Vector<>();
        names.add(CONFIG_KEY_TYPE);
        names.add(CONFIG_KEY_PARAMETERS);
        ConfigStore keys = getAllowedKeysStore();
        if (keys != null) {
            try {
                Enumeration<String> en = keys.getPropertyNames();
                while (en.hasMoreElements()) {
                    names.add(CONFIG_ALLOWED_KEYS_PREFIX + en.nextElement());
                }
            } catch (Exception e) {
                logger.warn("KeyConstraint.getConfigNames: {}", e.getMessage());
            }
        }
        return names.elements();
    }

    @Override
    public String getConfig(String name, String defval) {
        if (name != null && name.startsWith(CONFIG_ALLOWED_KEYS_PREFIX)
                && name.length() > CONFIG_ALLOWED_KEYS_PREFIX.length()) {
            String leaf = name.substring(CONFIG_ALLOWED_KEYS_PREFIX.length());
            ConfigStore keys = getAllowedKeysStore();
            if (keys != null) {
                try {
                    return keys.getString(leaf, defval);
                } catch (EBaseException e) {
                    logger.warn("KeyConstraint.getConfig allowedKeys.{}: {}", leaf, e.getMessage());
                    return defval;
                }
            }
            return defval;
        }
        return super.getConfig(name, defval);
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    @Override
    public void validate(Request request, X509CertInfo info)
            throws ERejectException {
        try {
            CertificateX509Key infokey = (CertificateX509Key) info.get(X509CertInfo.KEY);
            X509Key key = (X509Key) infokey.get(CertificateX509Key.KEY);
            String alg = key.getAlgorithmId().getName().toUpperCase();
            logger.info("KeyConstraint: Key algorithnm: " + alg);

            String value = getConfig(CONFIG_KEY_TYPE);
            logger.info("KeyConstraint: Key type: " + value);

            String keyType = value;

            if (!isOptional(value)) {
                String algKey = alg.startsWith("ML-DSA-") ? "MLDSA" : alg;
                if (!algKey.equals(value)) {
                    logger.error("Invalid key type: " + value);
                    throw new ERejectException(
                            CMS.getUserMessage(
                                    getLocale(request),
                                    "CMS_PROFILE_KEY_TYPE_NOT_MATCHED",
                                    value));
                }
            }

            int keySize = 0;

            if (alg.equals("RSA")) {
                keySize = getRSAKeyLen(key);
            } else if (alg.equals("DSA")) {
                keySize = getDSAKeyLen(key);
            } else if (alg.startsWith("ML-DSA-")) {
                keySize = Integer.parseInt(alg.replaceFirst("^ML-DSA-", ""));
            } else if (alg.equals("EC")) {
                //EC key case.
            } else {
                throw new ERejectException(
                        CMS.getUserMessage(
                                getLocale(request),
                                "CMS_PROFILE_INVALID_KEY_TYPE",
                                alg));
            }

            value = getConfig(CONFIG_KEY_PARAMETERS);

            String[] keyParams = (value != null) ? value.split(",") : new String[0];
       
            Map<String, Map<String, String>> allowedKeysMap = mapAllowedKeys();

            if (keyParams.length > 0) {
                logger.warn("KeyConstraint.validate: use of {} is DEPRECATED, use {} instead", CONFIG_KEY_PARAMETERS, CONFIG_ALLOWED_KEYS_PARAM);
                if (allowedKeysMap.size() > 0) {
                    logger.error("Invalid Configuration: can't mix {} and {}", CONFIG_ALLOWED_KEYS_PARAM, CONFIG_KEY_PARAMETERS);
                    throw new EPropertyException(CMS.getUserMessage("CMS_MIXED_KEY_CONFIGURATION", CONFIG_ALLOWED_KEYS_PARAM, CONFIG_KEY_PARAMETERS));
                }
                logger.debug("{}: {}", CONFIG_KEY_PARAMETERS, value);
            }

            if (alg.equals("EC")) {
                if (!alg.equals(keyType) && !isOptional(keyType)) {
                    logger.error("Invalid key type: " + keyType);
                    throw new ERejectException(
                            CMS.getUserMessage(
                                    getLocale(request),
                                    "CMS_PROFILE_KEY_PARAMS_NOT_MATCHED",
                                    value));
                }

                Vector<?> vect = CryptoUtil.getECKeyCurve(key);

                boolean curveFound = false;

                if (vect != null) {
                    logger.debug("vect: " + vect);

                    Set<String> ecKeys = getAllowedKeysForAlgorithm(keyParams, allowedKeysMap, "EC");
                    if (!isOptional(keyType)) {
                        //Check the curve parameters only if explicit ECC or not optional
                        for (String ecParam : ecKeys) {
                            logger.debug("EC key parameter: " + ecParam);
                            if (vect.contains(ecParam)) {
                                curveFound = true;
                                logger.debug("KeyConstraint.validate: EC key constrainst passed.");
                                break;
                            }
                        }
                    } else {
                        curveFound = true;
                    }
                }

                if (!curveFound) {
                    String message = CMS.getUserMessage(
                            getLocale(request),
                            "CMS_PROFILE_KEY_PARAMS_NOT_MATCHED",
                            value);
                    logger.error("KeyConstraint.validate: EC key constrainst failed: " + message);
                    throw new ERejectException(message);
                }

            } else if (alg.startsWith("ML-DSA-")) {
                checkAllowedAlgorithm(keySize, value, keyParams, allowedKeysMap, "MLDSA", request);
            } else if (alg.equals("RSA")) {
                checkAllowedAlgorithm(keySize, value, keyParams, allowedKeysMap, "RSA", request);
            }
        } catch (Exception e) {
            if (e instanceof ERejectException) {
                throw (ERejectException) e;
            }
            logger.error("KeyConstraint: " + e.getMessage(), e);
            throw new ERejectException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_KEY_NOT_FOUND"));
        }
    }

    private void validateAlgorithmName(String algName) throws EPropertyException {
        String alg = algName.toUpperCase();
        if (alg.equals("RSA")) {
            return;
        } else if (alg.equals("DSA")) {
            return;
        } else if (alg.equals("ML-DSA") || alg.matches("^ML-DSA-\\d+$")) {
            return;
        } else if (alg.equals("EC")) {
            return;
        } else {
            throw new EPropertyException(CMS.getUserMessage("CMS_PROFILE_INVALID_KEY_TYPE", algName));
        }
    }

    public int getRSAKeyLen(X509Key key) throws Exception {
        X509Key newkey = null;

        try {
            newkey = new X509Key(AlgorithmId.get("RSA"),
                        key.getKey());
        } catch (Exception e) {
            logger.error("KeyConstraint: getRSAKey Len " + e.getMessage(), e);
            return -1;
        }
        RSAPublicKey rsaKey = new RSAPublicKey(newkey.getEncoded());

        return rsaKey.getKeySize();
    }

    public int getDSAKeyLen(X509Key key) throws Exception {
        // Check DSAKey parameters.
        // size refers to the p parameter.
        DSAPublicKey dsaKey = new DSAPublicKey(key.getEncoded());
        DSAParams keyParams = dsaKey.getParams();
        BigInteger p = keyParams.getP();
        int len = p.bitLength();

        return len;
    }

    @Override
    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_KEY_TYPE),
                getConfig(CONFIG_KEY_PARAMETERS)
            };

        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_KEY_TEXT", params);
    }

    @Override
    public boolean isApplicable(PolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof UserKeyDefault)
            return true;
        return false;
    }

    private void validateKeyParams(String name, String keyType, String keyParams) throws EPropertyException {

        if (KeyConstraint.allowedKeys.length() > 0 && KeyConstraint.keyParams.length() > 0) {
            logger.error("Invalid Configuration: can't mix {} and {}", CONFIG_ALLOWED_KEYS_PARAM, CONFIG_KEY_PARAMETERS);
            KeyConstraint.keyType = "";
            KeyConstraint.keyParams = "";
            KeyConstraint.allowedKeys = "";
            throw new EPropertyException(CMS.getUserMessage("CMS_MIXED_KEY_CONFIGURATION", CONFIG_ALLOWED_KEYS_PARAM, CONFIG_KEY_PARAMETERS));
        }

        // All the params we need for validation have been collected,
        // we don't know which order they will show up
        if (keyType.length() > 0 && keyParams.length() > 0) {
            String[] params = keyParams.split(",");
            boolean isECCurve = false;
            int keySize = 0;

            if (keyType.equals("EC")) {

                for (String param : params) {
                    logger.info("KeyConstraint: EC curve: " + param);

                    if (cfgECCurves == null) {
                        //Use the static array as a backup if the config values are not present.
                        isECCurve = arrayContainsString(CryptoUtil.getECcurves(), param);
                    } else {
                        isECCurve = arrayContainsString(cfgECCurves, param);
                    }

                    if (!isECCurve) {
                        logger.error("Invalid EC curve: " + param);
                        KeyConstraint.keyType = "";
                        KeyConstraint.keyParams = "";
                        KeyConstraint.allowedKeys = "";
                        throw new EPropertyException(CMS.getUserMessage("CMS_INVALID_PROPERTY", name));
                    }
                }

            } else if (keyType.equals("MLDSA")) {
                for (String param : params) {
                    if (param != null && !param.trim().isEmpty()) {
                        logger.info("KeyConstraint: MLDSA keyParameters token (not used for ML-DSA validation): " + param);
                    }
                }

            } else {

                for (String param : params) {
                    try {
                        logger.info("KeyConstraint: RSA key size: " + param);
                        keySize = Integer.parseInt(param);

                    } catch (NumberFormatException e) {
                        if (isOptional(keyType)) {
                            logger.info("KeyConstraint: EC curve: " + param);
                            isECCurve = arrayContainsString(CryptoUtil.getECcurves(), param);
                        }
                        keySize = 0;
                    }

                    if (keySize <= 0 && !isECCurve) {
                        logger.error("Invalid EC curve: " + param);
                        KeyConstraint.keyType = "";
                        KeyConstraint.keyParams = "";
                        KeyConstraint.allowedKeys = "";
                        throw new EPropertyException(CMS.getUserMessage("CMS_INVALID_PROPERTY", name));
                    }
                }
            }
        }
    }

    @Override
    public void setConfig(String name, String value)
            throws EPropertyException {

        logger.info("KeyConstraint: Setting " + name + ": " + value);

        if (name != null && name.startsWith(CONFIG_ALLOWED_KEYS_PREFIX)) {
            allowedKeys = value;
        }
        
        if (name != null && name.startsWith(CONFIG_ALLOWED_KEYS_PREFIX)
            && Optional.ofNullable(value).map(String::trim).filter("true"::equalsIgnoreCase).isPresent()
            && name.length() > CONFIG_ALLOWED_KEYS_PREFIX.length()
        ) {
            String leaf = name.substring(CONFIG_ALLOWED_KEYS_PREFIX.length());
            String[] parts = leaf.split("\\.", 2);
            if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
                throw new EPropertyException(CMS.getUserMessage("CMS_INVALID_PROPERTY", name));
            }
            String algType = parts[0].toUpperCase(Locale.ROOT);
            validateAlgorithmName(algType);
            String keyValue = parts[1];
            validateKeyParams(name, algType, keyValue);
        }

        //establish keyType, we don't know which order these params will arrive
        if (name.equals(CONFIG_KEY_TYPE)) {
            keyType = value;
            if (keyParams.equals(""))
                return;
        }

        //establish keyParams
        if (name.equals(CONFIG_KEY_PARAMETERS)) {
            keyParams = value;
            if (!value.equals("")) {
                logger.warn("KeyConstraint: use of {} is DEPRECATED, use {} instead", CONFIG_KEY_PARAMETERS, CONFIG_ALLOWED_KEYS_PARAM);
            }
            if (keyType.equals(""))
                return;
        }

        validateKeyParams(name, keyType, keyParams);

        //Actually set the configuration in the profile
        super.setConfig(CONFIG_KEY_TYPE, keyType);
        super.setConfig(CONFIG_KEY_PARAMETERS, keyParams);

        //Reset the vars for next round.
        keyType = "";
        keyParams = "";
    }

    private boolean arrayContainsString(String[] array, String value) {

        if (array == null || value == null) {
            return false;
        }

        for (int i = 0; i < array.length; i++) {
            if (array[i].equals(value)) {
                return true;
            }
        }

        return false;
    }
}
