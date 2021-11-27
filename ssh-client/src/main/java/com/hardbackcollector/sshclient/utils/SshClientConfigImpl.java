package com.hardbackcollector.sshclient.utils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.Random;
import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.ciphers.SshCipherConstants;
import com.hardbackcollector.sshclient.hostconfig.HostConfigRepository;
import com.hardbackcollector.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbackcollector.sshclient.kex.KexProposal;
import com.hardbackcollector.sshclient.kex.keyexchange.KeyExchangeConstants;
import com.hardbackcollector.sshclient.macs.SshMacConstants;
import com.hardbackcollector.sshclient.signature.SshSignature;
import com.hardbackcollector.sshclient.userauth.UserAuthGSSAPIWithMIC;
import com.hardbackcollector.sshclient.userauth.UserAuthKeyboardInteractive;
import com.hardbackcollector.sshclient.userauth.UserAuthNone;
import com.hardbackcollector.sshclient.userauth.UserAuthPassword;
import com.hardbackcollector.sshclient.userauth.UserAuthPublicKey;
import com.hardbackcollector.sshclient.userauth.jgss.UserAuthGSSContextKrb5;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@SuppressWarnings("WeakerAccess")
public class SshClientConfigImpl
        implements SshClientConfig {

    // jc stands for jcraft or for java-client; your choice...
    public static final String SYS_PROP_PREFIX = "sshjc.";
    public static final int DEFAULT_NUMBER_OF_PASSWORD_PROMPTS = 3;

    private final Map<String, String> config = new HashMap<>();
    @Nullable
    private final SshClientConfigImpl parentConfig;
    @Nullable
    private Random random;

    public SshClientConfigImpl() {
        this.parentConfig = null;
        loadDefaultConfig();
    }

    public SshClientConfigImpl(@Nullable final SshClientConfigImpl parentConfig) {
        this.parentConfig = parentConfig;
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
    @Nullable
    public String getString(@NonNull final String key) {
        final String value;
        value = config.get(key);
        if (value != null) {
            return value;
        }

        return parentConfig != null ? parentConfig.getString(key) : null;
    }

    @NonNull
    @Override
    public Random getRandom()
            throws NoSuchAlgorithmException {
        synchronized (this) {
            if (random == null) {
                if (parentConfig != null) {
                    random = parentConfig.getRandom();
                } else {
                    random = ImplementationFactory.getRandom(this);
                }
            }
        }
        return random;
    }

    public boolean isValidateAlgorithmClasses() {
        return getBooleanValue(ImplementationFactory.PK_VALIDATE_ALGORITHM_CLASSES, true);
    }

    public boolean isClearAllForwards() {
        return getBooleanValue(HostConfigRepository.HostConfig.CLEAR_ALL_FORWARDS, false);
    }

    @Override
    public int getNumberOfPasswordPrompts() {
        return getIntValue(HostConfigRepository.HostConfig.NUMBER_OF_PASSWORD_PROMPTS,
                DEFAULT_NUMBER_OF_PASSWORD_PROMPTS);
    }

    @Override
    @NonNull
    public List<String> getPublicKeyAcceptedAlgorithms() {
        final Set<String> all = new HashSet<>();
        final List<String> a1 = getStringList(HostConfigRepository.HostConfig
                .PUBKEY_ACCEPTED_ALGORITHMS);
        if (!a1.isEmpty()) {
            all.addAll(a1);
        }
        final List<String> a2 = getStringList(HostConfigRepository.HostConfig
                .PUBKEY_ACCEPTED_KEY_TYPES);
        if (!a2.isEmpty()) {
            all.addAll(a2);
        }

        if (all.isEmpty()) {
            return new ArrayList<>();
        }

        if (!isValidateAlgorithmClasses()) {
            return new ArrayList<>(all);
        }

        final List<String> result = new ArrayList<>();
        for (final String name : all) {
            try {
                final SshSignature sig = ImplementationFactory.getSignature(this, name);
                sig.init(name);
                result.add(name);
            } catch (final GeneralSecurityException ignore) {
                // ignore
            }
        }

        return result;
    }

    /**
     * Load the default configuration.
     * <p>
     * Not explicitly added here are options which have their defaults already in the code,
     * and cannot "not defined".
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
            putFromSystemProperty(KexProposal.PROPOSAL_KEX_ALGS,
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
            putFromSystemProperty(KexProposal.CHECK_KEX_ALGS,
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
            putFromSystemProperty(KexProposal.PROPOSAL_HOST_KEY_ALGS,
                    HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256
                            + ',' + HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384
                            + ',' + HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521
                            + ',' + HostKeyAlgorithm.SSH_ED25519
                            + ',' + HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_512
                            + ',' + HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_256
                            + ',' + HostKeyAlgorithm.SSH_RSA
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
            putFromSystemProperty(KexProposal.PROPOSAL_ENC_ALGS_CTOS,
                    SshCipherConstants.CHACHA20_POLY1305_OPENSSH_COM
                            + ',' + SshCipherConstants.AES_128_CTR
                            + ',' + SshCipherConstants.AES_192_CTR
                            + ',' + SshCipherConstants.AES_256_CTR
                            + ',' + SshCipherConstants.AES_128_GCM_OPENSSH_COM
                            + ',' + SshCipherConstants.AES_256_GCM_OPENSSH_COM
            );
            putFromSystemProperty(KexProposal.PROPOSAL_ENC_ALGS_STOC,
                    SshCipherConstants.CHACHA20_POLY1305_OPENSSH_COM
                            + ',' + SshCipherConstants.AES_128_CTR
                            + ',' + SshCipherConstants.AES_192_CTR
                            + ',' + SshCipherConstants.AES_256_CTR
                            + ',' + SshCipherConstants.AES_128_GCM_OPENSSH_COM
                            + ',' + SshCipherConstants.AES_256_GCM_OPENSSH_COM
            );

            // These will be tested to see if their implementations CAN be instantiated.
            // If not, they will be removed from the above list BEFORE it is send to the
            // server. Disable with {@link KexProposal#CHECKS_ARE_DISABLED}
            putFromSystemProperty(KexProposal.CHECK_ENC_ALGS,
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
            putFromSystemProperty(KexProposal.PROPOSAL_MAC_ALGS_STOC,
                    SshMacConstants.HMAC_SHA_2_256_ETM_OPENSSH_COM
                            + ',' + SshMacConstants.HMAC_SHA_2_512_ETM_OPENSSH_COM
                            + ',' + SshMacConstants.HMAC_SHA_1_ETM_OPENSSH_COM
                            + ',' + SshMacConstants.HMAC_SHA_2_256
                            + ',' + SshMacConstants.HMAC_SHA_2_512
                            + ',' + SshMacConstants.HMAC_SHA_1
            );
            putFromSystemProperty(KexProposal.PROPOSAL_MAC_ALGS_CTOS,
                    SshMacConstants.HMAC_SHA_2_256_ETM_OPENSSH_COM
                            + ',' + SshMacConstants.HMAC_SHA_2_512_ETM_OPENSSH_COM
                            + ',' + SshMacConstants.HMAC_SHA_1_ETM_OPENSSH_COM
                            + ',' + SshMacConstants.HMAC_SHA_2_256
                            + ',' + SshMacConstants.HMAC_SHA_2_512
                            + ',' + SshMacConstants.HMAC_SHA_1
            );

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

            putFromSystemProperty(HostConfigRepository.HostConfig.PREFERRED_AUTHENTICATIONS,
                    UserAuthGSSAPIWithMIC.METHOD
                            + ',' + UserAuthPublicKey.METHOD
                            + ',' + UserAuthKeyboardInteractive.METHOD
                            + ',' + UserAuthPassword.METHOD
            );

            putFromSystemProperty(HostConfigRepository.HostConfig.PUBKEY_ACCEPTED_ALGORITHMS,
                    HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256
                            + ',' + HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384
                            + ',' + HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521
                            + ',' + HostKeyAlgorithm.SSH_ED25519
                            + ',' + HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_512
                            + ',' + HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_256
                            + ',' + HostKeyAlgorithm.SSH_RSA
            );
        }
    }
}
