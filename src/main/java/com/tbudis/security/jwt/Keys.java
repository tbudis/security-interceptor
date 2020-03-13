package com.tbudis.security.jwt;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;

import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Create and cache various keys used in the services.
 *
 * @author titus
 */
public class Keys {

    /** Logger. */
    private static Logger logger = LoggerFactory.getLogger(Keys.class);

    /** Path of custom secret key in the config file. */
    private static final String SECRET_KEY_CONFIG_PATH = "jwt.secret.key";

    /** Path of custom certificate file name in the config file. */
    private static final String CERTIFICATE_FILE_CONFIG_PATH = "jwt.certificate.file";

    /** The full file path of user services config file. */
    private static final String APPLICATION_LEVEL_PATH = getConfigurationPath() + "/etc/security.conf";

    /** Wildfly config dir in deployment. */
    private static String getConfigurationPath() {
        return System.getProperty("jboss.server.config.dir");
    }

    /** Config object. */
    private static Config config;

    /** Auth0 secret key based on HS256 algorithm. */
    public static Key secretKey;

    /** Auth0 public key based on certificate issued by Auth0. */
    public static Key publicKey;

    static {
        config = ConfigFactory.parseFile(new File(APPLICATION_LEVEL_PATH));
        secretKey = createSecretKey();
        publicKey = createPublicKey();
    }

    /**
     * Create private key based on the secret key.
     *
     * @return
     */
    private static SecretKey createSecretKey() {
        // secret is Base64 encoded
        String secretKey = "";

        // override with custom value (if any)
        if (config.hasPath(SECRET_KEY_CONFIG_PATH)) {
            String value = config.getString(SECRET_KEY_CONFIG_PATH);
            if (StringUtils.isNotBlank(value)) {
                secretKey = value;
                logger.info("Override secret key");
            }
        }

        byte[] apiKeySecretBytes = Base64.decodeBase64(secretKey);
        return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    /**
     * Create public key based on public certificate from Auth0.
     *
     * @return
     */
    private static PublicKey createPublicKey() {
        try {
            InputStream inputStream = null;

            // override with custom value (if any)
            if (config.hasPath(CERTIFICATE_FILE_CONFIG_PATH)) {
                String value = config.getString(CERTIFICATE_FILE_CONFIG_PATH);
                if (StringUtils.isNotBlank(value)) {
                    try {
                        String certFilePath = getConfigurationPath() + value;
                        inputStream = FileUtils.openInputStream(new File(certFilePath));
                        logger.info("Override public certificate");
                    } catch (IOException e) {
                        logger.error("Error reading custom public certificate. Use the default certificate.", e);
                    }
                }
            }

            if (inputStream == null) {
                logger.error("No public certificate available");
                return null;
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);
            return cert.getPublicKey();
        } catch (CertificateException e) {
            logger.error(e.getMessage());
            return null;
        }
    }
}
