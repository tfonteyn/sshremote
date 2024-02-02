package com.hardbacknutter.sshclient.utils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.Random;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.SshSessionConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipherConstants;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.kex.KexDelegate;
import com.hardbacknutter.sshclient.kex.KexProposal;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeConstants;
import com.hardbacknutter.sshclient.macs.SshMacConstants;
import com.hardbacknutter.sshclient.userauth.UserAuthGSSAPIWithMIC;
import com.hardbacknutter.sshclient.userauth.UserAuthKeyboardInteractive;
import com.hardbacknutter.sshclient.userauth.UserAuthNone;
import com.hardbacknutter.sshclient.userauth.UserAuthPassword;
import com.hardbacknutter.sshclient.userauth.UserAuthPublicKey;
import com.hardbacknutter.sshclient.userauth.jgss.UserAuthGSSContextKrb5;

/**
 * Each {@link SshClient} has ONE configuration object.
 * A new {@link Session} created from that client inherits the configuration,
 * but options/logger can be overridden on the session level.
 */
@SuppressWarnings("WeakerAccess")
public final class SshClientConfigImpl
        implements SshSessionConfig {

    /** The prefix for configuration options set as system properties. */
    public static final String SYS_PROP_PREFIX = "sshjc.";
    /**
     * The default logger implementation logs nothing.
     */
    public static final Logger DEV_NULL = new Logger() {
        @Override
        public boolean isEnabled(final int level) {
            return false;
        }

        @Override
        public void log(final int level,
                        @NonNull final String message) {

        }
    };

    private static final Set<String> KEY_IS_LIST_VALUE = Set.of(
            HostConfig.KEX_ALGS.toLowerCase(Locale.ENGLISH)
            , HostConfig.HOST_KEY_ALGS.toLowerCase(Locale.ENGLISH)
            , KexProposal.PROPOSAL_CIPHER_CTOS.toLowerCase(Locale.ENGLISH)
            , KexProposal.PROPOSAL_CIPHER_STOC.toLowerCase(Locale.ENGLISH)
            , KexProposal.PROPOSAL_MAC_CTOS.toLowerCase(Locale.ENGLISH)
            , KexProposal.PROPOSAL_MAC_STOC.toLowerCase(Locale.ENGLISH)
            , KexProposal.PROPOSAL_COMP_CTOS.toLowerCase(Locale.ENGLISH)
            , KexProposal.PROPOSAL_COMP_STOC.toLowerCase(Locale.ENGLISH)
            , KexProposal.PROPOSAL_LANG_CTOS.toLowerCase(Locale.ENGLISH)
            , KexProposal.PROPOSAL_LANG_STOC.toLowerCase(Locale.ENGLISH)
            , HostConfig.PREFERRED_AUTHENTICATIONS.toLowerCase(Locale.ENGLISH)
            , HostConfig.PUBLIC_KEY_ACCEPTED_ALGORITHMS.toLowerCase(Locale.ENGLISH)
            , HostConfig.PUBLIC_KEY_ACCEPTED_KEY_TYPES.toLowerCase(Locale.ENGLISH)

            , HostConfig.LOCAL_FORWARD.toLowerCase(Locale.ENGLISH)
            , HostConfig.REMOTE_FORWARD.toLowerCase(Locale.ENGLISH)
    );

    // FIRST try here, i.e. the local options.
    private final Map<String, String> config = new HashMap<>();
    // SECONDLY try the (optional) host configuration file which is set on the session
    @Nullable
    private final HostConfig hostConfig;
    // LASTLY try the parent configuration, i.e. the global SshClient options
    @Nullable
    private final SshClientConfig parentConfig;

    /**
     * The active logger. The configuration object is the owner of the Logger.
     * Any other object spun of should keep a reference to the config and
     * use {@link SshClientConfig#getLogger()}.
     */
    @NonNull
    private Logger logger;

    /** Random generator used by this config */
    @Nullable
    private Random random;

    /**
     * Private constructor. Always use the static factory methods to get the correct type back.
     */
    public SshClientConfigImpl(@Nullable final SshClientConfig parentConfig,
                               @Nullable final HostConfig hostConfig,
                               @Nullable final Logger logger) {
        this.parentConfig = parentConfig;
        this.hostConfig = hostConfig;
        this.logger = Objects.requireNonNullElse(logger, DEV_NULL);
        loadDefaultConfig();
    }

    /**
     * Construct an {@link SshClient} configuration.
     *
     * @return a {@link SshClientConfig}
     */
    @NonNull
    public static SshClientConfig createClientConfig(@Nullable final Logger logger) {
        return new SshClientConfigImpl(null, null, logger);
    }

    @NonNull
    @Override
    public Logger getLogger() {
        return logger;
    }

    @Override
    public void setLogger(@Nullable final Logger logger) {
        this.logger = Objects.requireNonNullElse(logger, DEV_NULL);
    }

    @Override
    @Nullable
    public HostConfig getHostConfig() {
        return hostConfig;
    }

    @NonNull
    public Random getRandom()
            throws NoSuchAlgorithmException {
        synchronized (this) {
            if (random == null) {
                random = ImplementationFactory.getRandom(this);
            }
        }
        return random;
    }

    @Override
    @NonNull
    public Map<String, String> getAll() {
        return config;
    }

    @Override
    public void putAll(@NonNull final Map<String, String> newConf) {
        synchronized (config) {
            config.putAll(newConf);
        }
    }

    @Override
    public void putString(@NonNull final String key,
                          @NonNull final String value) {
        config.put(key, value);
    }

    /**
     * Set a config option by looking up the system property
     * {@link #SYS_PROP_PREFIX}configKey,
     * or use the passed default value.
     *
     * @param configKey config key
     * @param defValue  to use
     */
    public void putFromSystemProperty(@NonNull final String configKey,
                                      @NonNull final String defValue) {
        try {
            config.put(configKey, System.getProperty(SYS_PROP_PREFIX + configKey, defValue));
        } catch (final SecurityException ignore) {
            config.put(configKey, defValue);
        }
    }

    @Override
    public boolean isValueList(@NonNull final String key) {
        return KEY_IS_LIST_VALUE.contains(key.toLowerCase(Locale.ENGLISH));
    }

    @Override
    @Nullable
    public String getString(@NonNull final String key,
                            @Nullable final String defValue) {
        if (isValueList(key)) {
            return getListOption(key, defValue);
        } else {
            return getSingleOption(key, defValue);
        }
    }

    @Nullable
    private String getSingleOption(@NonNull final String key,
                                   @Nullable final String defValue) {
        // For a single option, we check all levels using 'null' as the default.
        // Only when no levels have our option, we will return the 'defValue'.
        String value;

        // if this session configuration has the value, just return it.
        value = config.get(key);
        if (value != null) {
            return value;
        }

        // otherwise check the session specific host configuration
        value = hostConfig != null ? hostConfig.getString(key, null) : null;
        if (value != null) {
            return value;
        }

        // use the parent; this will again first check the parent/global options,
        // followed by the parent/global host configuration
        value = parentConfig != null ? parentConfig.getString(key, null) : null;
        if (value != null) {
            return value;
        }

        return defValue;
    }

    @Nullable
    private String getListOption(@NonNull final String key,
                                 @Nullable final String defValue) {

        final String value = config.get(key);

        // ALWAYS accumulate with the host configuration regardless of the session value
        if (hostConfig != null) {
            final String h = hostConfig.getString(key, value);
            if (h != null && !h.isBlank()) {
                return h;
            }
        }

        // If we have no session value, go check the parent/global configuration
        // using the original default value
        if (value == null || value.isBlank()) {
            if (parentConfig != null) {
                final String p = parentConfig.getString(key, defValue);
                if (p != null && !p.isBlank()) {
                    return p;
                }
            }
        }

        if (value == null || value.isBlank()) {
            return defValue;
        } else {
            return value;
        }
    }

    /**
     * Load the default configuration.
     * <p>
     * Not explicitly added here are options which have their defaults already in the code,
     * and cannot be "not defined".
     * Overriding them would use the below with custom class names.
     * <pre>
     *     {@code
     *         // Compression: the keys consist of the prefix "inflate." or  "deflate."
     *         // + the standard ssh name for the compression protocol.
     *         {
     *              putClass(DEFLATER_CONFIG_PREFIX + KexProposal.COMPRESSION_ZLIB,
     *                         SshDeflaterImpl.class);
     *              putClass(INFLATER_CONFIG_PREFIX + KexProposal.COMPRESSION_ZLIB,
     *                         SshInflaterImpl.class);
     *
     *              putClass(DEFLATER_CONFIG_PREFIX + KexProposal.COMPRESSION_ZLIB_OPENSSH_COM,
     *                         SshDeflaterImpl.class);
     *              putClass(INFLATER_CONFIG_PREFIX + KexProposal.COMPRESSION_ZLIB_OPENSSH_COM,
     *                         SshInflaterImpl.class);
     *         }
     *          // The random provider, defaults to {@link java.security.SecureRandom}
     *          putClass(Random.RANDOM, RandomImpl.class);
     * </pre>
     */
    private void loadDefaultConfig() {
        // SSH_MSG_KEXINIT

        // string    kex_algorithms
        // string    server_host_key_algorithms
        // string    encryption_algorithms_client_to_server
        // string    encryption_algorithms_server_to_client
        // string    mac_algorithms_client_to_server
        // string    mac_algorithms_server_to_client
        // string    compression_algorithms_client_to_server
        // string    compression_algorithms_server_to_client
        // string    languages_client_to_server
        // string    languages_server_to_client

        // kex_algorithms (KeyExchange)
        // https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3
        {
            // The list send to the server
            // https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-kex-sha2-03#section-4
            putFromSystemProperty(
                    HostConfig.KEX_ALGS,
                    KeyExchangeConstants.CURVE_25519_SHA_256
                            + ',' + KeyExchangeConstants.CURVE_25519_SHA_256_LIBSSH_ORG
                            + ',' + KeyExchangeConstants.ECDH_SHA_2_NISTP_256
                            + ',' + KeyExchangeConstants.ECDH_SHA_2_NISTP_384
                            + ',' + KeyExchangeConstants.ECDH_SHA_2_NISTP_521
                            + ',' + KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_256
                            + ',' + KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_16_SHA_512
                            + ',' + KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_18_SHA_512
                            + ',' + KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_14_SHA_256
            );

            // These will be tested to see if their implementations CAN be instantiated.
            // If not, they will be removed from the above list before it is send to the
            // server. Disable with {@link KexProposal#CHECKS_ARE_DISABLED}
            putFromSystemProperty(
                    KexProposal.CHECK_KEX_ALGS,
                    KeyExchangeConstants.CURVE_25519_SHA_256
                            + ',' + KeyExchangeConstants.CURVE_25519_SHA_256_LIBSSH_ORG
                            + ',' + KeyExchangeConstants.CURVE_448_SHA_512
                            + ',' + KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_14_SHA_1
                            + ',' + KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_14_SHA_256
                            + ',' + KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_15_SHA_512
                            + ',' + KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_16_SHA_512
                            + ',' + KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_17_SHA_512
                            + ',' + KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_18_SHA_512
                            + ',' + KeyExchangeConstants.ECDH_SHA_2_NISTP_256
                            + ',' + KeyExchangeConstants.ECDH_SHA_2_NISTP_384
                            + ',' + KeyExchangeConstants.ECDH_SHA_2_NISTP_521
            );
        }

        // server_host_key_algorithms (Signature):
        {
            // The list send to the server
            putFromSystemProperty(HostConfig.HOST_KEY_ALGS,
                                  HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256
                                          + ',' + HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384
                                          + ',' + HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521
                                          + ',' + HostKeyAlgorithm.SSH_ED25519
                                          + ',' + HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_512
                                          + ',' + HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_256
            );

            // These will be tested to see if their implementations CAN be instantiated.
            // If not, they will be removed from the above list BEFORE it is send to the
            // server. Disable with {@link KexProposal#CHECKS_ARE_DISABLED}
            putFromSystemProperty(KexProposal.CHECK_SIG_ALGS,
                                  HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_512
                                          + ',' + HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_256
                                          + ',' + HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521
                                          + ',' + HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384
                                          + ',' + HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256
                                          + ',' + HostKeyAlgorithm.SSH_ED25519
                                          + ',' + HostKeyAlgorithm.SSH_ED448
            );
        }

        // encryption_algorithms (Ciphers)
        {
            // The list send to the server
            final String ciphers = SshCipherConstants.CHACHA20_POLY1305_OPENSSH_COM
                    + ',' + SshCipherConstants.AES_128_CTR
                    + ',' + SshCipherConstants.AES_192_CTR
                    + ',' + SshCipherConstants.AES_256_CTR
                    + ',' + SshCipherConstants.AES_128_GCM_OPENSSH_COM
                    + ',' + SshCipherConstants.AES_256_GCM_OPENSSH_COM;
            putFromSystemProperty(KexProposal.PROPOSAL_CIPHER_CTOS, ciphers);
            putFromSystemProperty(KexProposal.PROPOSAL_CIPHER_STOC, ciphers);

            // These will be tested to see if their implementations CAN be instantiated.
            // If not, they will be removed from the above list BEFORE it is send to the
            // server. Disable with {@link KexProposal#CHECKS_ARE_DISABLED}
            putFromSystemProperty(KexProposal.CHECK_CIP_ALGS,
                                  SshCipherConstants.CHACHA20_POLY1305_OPENSSH_COM
                                          + ',' + SshCipherConstants.AES_128_GCM_OPENSSH_COM
                                          + ',' + SshCipherConstants.AES_256_GCM_OPENSSH_COM
                                          + ',' + SshCipherConstants.AES_128_CTR
                                          + ',' + SshCipherConstants.AES_192_CTR
                                          + ',' + SshCipherConstants.AES_256_CTR
                                          + ',' + SshCipherConstants.AES_128_CBC
                                          + ',' + SshCipherConstants.AES_192_CBC
                                          + ',' + SshCipherConstants.AES_256_CBC
                                          + ',' + SshCipherConstants.TRIPLE_DES_CTR
            );
        }

        // mac_algorithms (HMAC)
        {
            // The list send to the server
            final String macs = SshMacConstants.HMAC_SHA_2_256_ETM_OPENSSH_COM
                    + ',' + SshMacConstants.HMAC_SHA_2_512_ETM_OPENSSH_COM
                    + ',' + SshMacConstants.HMAC_SHA_1_ETM_OPENSSH_COM
                    + ',' + SshMacConstants.HMAC_SHA_2_256
                    + ',' + SshMacConstants.HMAC_SHA_2_512
                    + ',' + SshMacConstants.HMAC_SHA_1;
            putFromSystemProperty(KexProposal.PROPOSAL_MAC_STOC, macs);
            putFromSystemProperty(KexProposal.PROPOSAL_MAC_CTOS, macs);

            // These will be tested to see if their implementations CAN be instantiated.
            // If not, they will be removed from the above list BEFORE it is send to the
            // server. Disable with {@link KexProposal#CHECKS_ARE_DISABLED}
            putFromSystemProperty(KexProposal.CHECK_MAC_ALGS,
                                  SshMacConstants.HMAC_SHA_2_256_ETM_OPENSSH_COM
                                          + ',' + SshMacConstants.HMAC_SHA_2_512_ETM_OPENSSH_COM
                                          + ',' + SshMacConstants.HMAC_SHA_2_256
                                          + ',' + SshMacConstants.HMAC_SHA_2_512
            );
        }

        // Authentication: the keys consist of the prefix "userauth."
        // + the standard ssh name for the authentication protocol.
        {
            putClass(ImplementationFactory.USERAUTH_CONFIG_PREFIX
                             + UserAuthNone.METHOD,
                     UserAuthNone.class);
            putClass(ImplementationFactory.USERAUTH_CONFIG_PREFIX
                             + UserAuthPassword.METHOD,
                     UserAuthPassword.class);
            putClass(ImplementationFactory.USERAUTH_CONFIG_PREFIX
                             + UserAuthKeyboardInteractive.METHOD,
                     UserAuthKeyboardInteractive.class);
            putClass(ImplementationFactory.USERAUTH_CONFIG_PREFIX
                             + UserAuthPublicKey.METHOD,
                     UserAuthPublicKey.class);
            putClass(ImplementationFactory.USERAUTH_CONFIG_PREFIX
                             + UserAuthGSSAPIWithMIC.METHOD,
                     UserAuthGSSAPIWithMIC.class);

            // The supported 'method' for "userauth.gssapi-with-mic"
            putClass(ImplementationFactory.USERAUTH_CONFIG_PREFIX
                             + UserAuthGSSContextKrb5.METHOD,
                     UserAuthGSSContextKrb5.class);

            putFromSystemProperty(HostConfig.PREFERRED_AUTHENTICATIONS,
                                  UserAuthGSSAPIWithMIC.METHOD
                                          + ',' + UserAuthPublicKey.METHOD
                                          + ',' + UserAuthKeyboardInteractive.METHOD
                                          + ',' + UserAuthPassword.METHOD
            );

            putFromSystemProperty(HostConfig.PUBLIC_KEY_ACCEPTED_ALGORITHMS,
                                  HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256
                                          + ',' + HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384
                                          + ',' + HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521
                                          + ',' + HostKeyAlgorithm.SSH_ED25519
                                          + ',' + HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_512
                                          + ',' + HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_256
            );
        }

        // Custom configuration flags:
        {
            putFromSystemProperty(ImplementationFactory.PK_VALIDATE_ALGORITHM_CLASSES,
                                  "true");
            putFromSystemProperty(ImplementationFactory.PK_ENABLE_SERVER_SIG_ALGS,
                                  "true");


        }
    }
}
