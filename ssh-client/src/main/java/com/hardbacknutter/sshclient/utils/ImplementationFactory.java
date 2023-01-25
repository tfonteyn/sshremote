package com.hardbacknutter.sshclient.utils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.Random;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.AESGCMCipher;
import com.hardbacknutter.sshclient.ciphers.ChaCha20Poly1305;
import com.hardbacknutter.sshclient.ciphers.NullCipher;
import com.hardbacknutter.sshclient.ciphers.RC4Cipher;
import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.ciphers.SshCipherConstants;
import com.hardbacknutter.sshclient.ciphers.SshCipherImpl;
import com.hardbacknutter.sshclient.compression.SshDeflater;
import com.hardbacknutter.sshclient.compression.SshDeflaterImpl;
import com.hardbacknutter.sshclient.compression.SshInflater;
import com.hardbacknutter.sshclient.compression.SshInflaterImpl;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.kex.KexProposal;
import com.hardbacknutter.sshclient.kex.keyagreements.DH;
import com.hardbacknutter.sshclient.kex.keyagreements.DHImpl;
import com.hardbacknutter.sshclient.kex.keyagreements.ECDH;
import com.hardbacknutter.sshclient.kex.keyagreements.ECDHImpl;
import com.hardbacknutter.sshclient.kex.keyagreements.XDH;
import com.hardbacknutter.sshclient.kex.keyagreements.XDHImpl;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchange;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeConstants;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeDHGroup1;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeDHGroup14;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeDHGroup15;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeDHGroup16;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeDHGroup17;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeDHGroup18;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeDHGroupExchange;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeECDH;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeEdDSA;
import com.hardbacknutter.sshclient.keypair.ECKeyType;
import com.hardbacknutter.sshclient.macs.SshMac;
import com.hardbacknutter.sshclient.macs.SshMacConstants;
import com.hardbacknutter.sshclient.macs.SshMacImpl;
import com.hardbacknutter.sshclient.signature.SshSignature;
import com.hardbacknutter.sshclient.signature.SshSignatureDSA;
import com.hardbacknutter.sshclient.signature.SshSignatureEd25519;
import com.hardbacknutter.sshclient.signature.SshSignatureEd448;
import com.hardbacknutter.sshclient.signature.SshSignatureRSA;
import com.hardbacknutter.sshclient.userauth.UserAuth;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@SuppressWarnings("WeakerAccess")
public final class ImplementationFactory {

    public static final String USERAUTH_CONFIG_PREFIX = "userauth.";
    public static final String INFLATER_CONFIG_PREFIX = "inflate.";
    public static final String DEFLATER_CONFIG_PREFIX = "deflate.";
    /**
     * Set to {@code "false"} to DISABLE all algorithm checking for a faster startup
     * in controlled environments. The default is {@code "true"} - enabled.
     * <p>
     * Valid for kex proposals + all others places where algorithms or key sizes might
     * not be available; e.g. public key accepted algorithms.
     */
    public static final String PK_VALIDATE_ALGORITHM_CLASSES =
            "validate_algorithm_classes";
    public static final String ERROR_ALGORITHM_NOT_FOUND =
            "Algorithm not found, or failed to instantiate: ";

    private ImplementationFactory() {
    }

    /**
     * Load a class using the given config key.
     * <p>
     * This method is used for loading generic security classes, where the config keys
     * are potentially not known at compile time.
     *
     * @param configKey  the configuration key to lookup the class name
     * @param asSubclass the (interface) class type which must be returned
     *                   (to ensure the configured class is the right type)
     *
     * @return a new instance of the desired class
     *
     * @throws NoSuchAlgorithmException when the key was invalid or the class failed to load
     * @throws ClassCastException       if the class instantiated does not implement the
     *                                  desired interface
     */
    @NonNull
    public static <T> T loadClassOrThrow(@NonNull final SshClientConfig config,
                                         @Nullable final String configKey,
                                         @NonNull final Class<? extends T> asSubclass)
            throws NoSuchAlgorithmException {
        if (configKey == null || configKey.isBlank()) {
            throw new NoSuchAlgorithmException("No algorithm name given");
        }

        final String className = config.getString(configKey);
        if (className == null || className.isBlank()) {
            throw new NoSuchAlgorithmException("No class configured for " + configKey);
        }

        try {
            final Class<? extends T> c = Class.forName(className).asSubclass(asSubclass);
            return c.getDeclaredConstructor().newInstance();
        } catch (final Exception e) {
            throw new NoSuchAlgorithmException("Failed to instantiate "
                                                       + className + " for " + configKey, e);
        }
    }

    /**
     * Load a class using the given config key.
     * <p>
     * If the config key is not found, the given {@code defClassName} is used.
     * If the class fails to load, an exception is thrown.
     *
     * @param configKey  the configuration key to lookup the class name
     * @param defClass   the class to use if the lookup fails
     * @param asSubclass the (interface) class type which must be returned
     *                   (to ensure the configured class is the right type)
     *
     * @return a new instance of the desired class
     *
     * @throws NoSuchAlgorithmException when the key was invalid or when its value
     *                                  was identical to the default and the class failed to load
     * @throws IllegalStateException    this is a FATAL issue... even the default class did not load
     * @throws ClassCastException       if the class instantiated does not implement the
     *                                  desired interface
     */
    @NonNull
    public static <T> T loadClassOrDefault(@NonNull final SshClientConfig config,
                                           @NonNull final String configKey,
                                           @NonNull final Class<? extends T> defClass,
                                           @NonNull final Class<? extends T> asSubclass)
            throws NoSuchAlgorithmException {

        try {
            return loadClassOrThrow(config, configKey, asSubclass);

        } catch (final NoSuchAlgorithmException e) {
            // Either the configKey was invalid, it the class assigned to it failed to load.
            // sanity check the default NOT to be the same
            final String className = config.getString(configKey);
            if (defClass.getCanonicalName().equals(className)) {
                throw new NoSuchAlgorithmException("Failed to instantiate "
                                                           + className + " for " + configKey, e);
            }
        }

        // fallback to the default.
        try {
            return defClass.getDeclaredConstructor().newInstance();

        } catch (final Exception e) {
            // We have a SERIOUS problem...
            final String errMsg = "Failed to instantiate " + defClass.getCanonicalName()
                    + " for " + configKey;
            if (config.getLogger().isEnabled(Logger.FATAL)) {
                config.getLogger().log(Logger.FATAL, e, () -> errMsg);
            }

            throw new IllegalStateException(errMsg, e);
        }
    }

    @NonNull
    public static Random getRandom(@NonNull final SshClientConfig config)
            throws NoSuchAlgorithmException {
        return (Random) loadClassOrDefault(config, Random.RANDOM,
                                           RandomImpl.class, Random.class);
    }

    @NonNull
    public static DH getDHKeyAgreement(@NonNull final SshClientConfig config)
            throws NoSuchAlgorithmException {
        return (DH) loadClassOrDefault(config, KexProposal.KEY_AGREEMENT_DH,
                                       DHImpl.class, DH.class);
    }

    @NonNull
    public static ECDH getECDHKeyAgreement(@NonNull final SshClientConfig config)
            throws NoSuchAlgorithmException {
        return (ECDH) loadClassOrDefault(config, KexProposal.KEY_AGREEMENT_ECDH,
                                         ECDHImpl.class, ECDH.class);
    }

    @NonNull
    public static XDH getXDHKeyAgreement(@NonNull final SshClientConfig config)
            throws NoSuchAlgorithmException {
        return (XDH) loadClassOrDefault(config, KexProposal.KEY_AGREEMENT_XDH,
                                        XDHImpl.class, XDH.class);
    }

    /**
     * @param algorithm the KEX algorithm name
     */
    @NonNull
    public static KeyExchange getKeyExchange(@NonNull final SshClientConfig config,
                                             @Nullable final String algorithm)
            throws NoSuchAlgorithmException {

        if (algorithm == null || algorithm.isEmpty()) {
            throw new NoSuchAlgorithmException("No algorithm name given");
        }
        if (config.contains(algorithm)) {
            return loadClassOrThrow(config, algorithm, KeyExchange.class);
        }

        try {
            switch (algorithm) {
                case KeyExchangeConstants.ECDH_SHA_2_NISTP_256:
                    return new KeyExchangeECDH("SHA-256", ECKeyType.ECDSA_SHA2_NISTP256);
                case KeyExchangeConstants.ECDH_SHA_2_NISTP_384:
                    return new KeyExchangeECDH("SHA-384", ECKeyType.ECDSA_SHA2_NISTP384);
                case KeyExchangeConstants.ECDH_SHA_2_NISTP_521:
                    return new KeyExchangeECDH("SHA-512", ECKeyType.ECDSA_SHA2_NISTP521);

                case KeyExchangeConstants.CURVE_25519_SHA_256:
                case KeyExchangeConstants.CURVE_25519_SHA_256_LIBSSH_ORG:
                    return new KeyExchangeEdDSA("SHA-256", XDHParameterSpec.X25519,
                                                EdECObjectIdentifiers.id_X25519, 32);

                case KeyExchangeConstants.CURVE_448_SHA_512:
                    return new KeyExchangeEdDSA("SHA-512", XDHParameterSpec.X448,
                                                EdECObjectIdentifiers.id_X448, 57);

                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_1:
                    return new KeyExchangeDHGroupExchange("SHA-1");
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_224_SSH_COM:
                    return new KeyExchangeDHGroupExchange("SHA-224");
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_256:
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_256_SSH_COM:
                    return new KeyExchangeDHGroupExchange("SHA-256");
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_384_SSH_COM:
                    return new KeyExchangeDHGroupExchange("SHA-384");
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_512_SSH_COM:
                    return new KeyExchangeDHGroupExchange("SHA-512");

                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_1_SHA_1:
                    return new KeyExchangeDHGroup1();

                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_14_SHA_1:
                    return new KeyExchangeDHGroup14("SHA-1");
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_14_SHA_224_SSH_COM:
                    return new KeyExchangeDHGroup14("SHA-224");
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_14_SHA_256:
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_14_SHA_256_SSH_COM:
                    return new KeyExchangeDHGroup14("SHA-256");

                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_15_SHA_256_SSH_COM:
                    return new KeyExchangeDHGroup15("SHA-256");
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_15_SHA_384_SSH_COM:
                    return new KeyExchangeDHGroup15("SHA-384");
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_15_SHA_512:
                    return new KeyExchangeDHGroup15("SHA-512");

                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_16_SHA_384_SSH_COM:
                    return new KeyExchangeDHGroup16("SHA-384");
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_16_SHA_512:
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_16_SHA_512_SSH_COM:
                    return new KeyExchangeDHGroup16("SHA-512");

                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_17_SHA_512:
                    return new KeyExchangeDHGroup17();

                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_18_SHA_512:
                case KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_18_SHA_512_SSH_COM:
                    return new KeyExchangeDHGroup18();

                default:
                    throw new NoSuchAlgorithmException(ERROR_ALGORITHM_NOT_FOUND + algorithm);
            }
        } catch (final Exception e) {
            throw new NoSuchAlgorithmException(ERROR_ALGORITHM_NOT_FOUND + algorithm, e);
        }
    }

    @NonNull
    public static UserAuth getUserAuth(@NonNull final SshClientConfig config,
                                       @NonNull final String method)
            throws NoSuchAlgorithmException {
        return loadClassOrThrow(config, USERAUTH_CONFIG_PREFIX + method, UserAuth.class);
    }

    @NonNull
    public static SshSignature getSignature(@NonNull final SshClientConfig config,
                                            @Nullable final String algorithm)
            throws NoSuchAlgorithmException {

        if (algorithm == null || algorithm.isBlank()) {
            throw new NoSuchAlgorithmException("No algorithm name given");
        }
        if (config.contains(algorithm)) {
            return loadClassOrThrow(config, algorithm, SshSignature.class);
        }

        try {
            switch (algorithm) {
                case HostKeyAlgorithm.SSH_DSS:
                    return new SshSignatureDSA("SHA1withDSA");
                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256:
                    return new SshSignatureDSA("SHA256withECDSA");
                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384:
                    return new SshSignatureDSA("SHA384withECDSA");
                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521:
                    return new SshSignatureDSA("SHA512withECDSA");

                case HostKeyAlgorithm.SSH_RSA:
                    return new SshSignatureRSA("SHA1withRSA");
                case HostKeyAlgorithm.SIG_ONLY_RSA_SHA_224_SSH_COM:
                    return new SshSignatureRSA("SHA224withRSA");
                case HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_256:
                case HostKeyAlgorithm.SIG_ONLY_RSA_SHA_256_SSH_COM:
                    return new SshSignatureRSA("SHA256withRSA");
                case HostKeyAlgorithm.SIG_ONLY_RSA_SHA_384_SSH_COM:
                    return new SshSignatureRSA("SHA384withRSA");
                case HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_512:
                case HostKeyAlgorithm.SIG_ONLY_RSA_SHA_512_SSH_COM:
                    return new SshSignatureRSA("SHA512withRSA");

                case HostKeyAlgorithm.SSH_ED25519:
                    return new SshSignatureEd25519();
                case HostKeyAlgorithm.SSH_ED448:
                    return new SshSignatureEd448();

                default:
                    throw new NoSuchAlgorithmException(ERROR_ALGORITHM_NOT_FOUND + algorithm);
            }
        } catch (final Exception e) {
            throw new NoSuchAlgorithmException(ERROR_ALGORITHM_NOT_FOUND + algorithm, e);
        }
    }

    public static SshCipher getCipher(@NonNull final SshClientConfig config,
                                      @Nullable final String algorithm)
            throws NoSuchAlgorithmException {

        if (algorithm == null || algorithm.isEmpty()) {
            throw new NoSuchAlgorithmException("No algorithm name given");
        }
        if (config.contains(algorithm)) {
            return loadCipherOrThrow(config, algorithm);
        }

        try {
            switch (algorithm) {
                case SshCipherConstants.CHACHA20_POLY1305_OPENSSH_COM:
                    return new ChaCha20Poly1305();

                case SshCipherConstants.AES_128_GCM_OPENSSH_COM:
                    return new AESGCMCipher("AES", "GCM", "NoPadding", 16, 16, 12);
                case SshCipherConstants.AES_256_GCM_OPENSSH_COM:
                    return new AESGCMCipher("AES", "GCM", "NoPadding", 16, 32, 12);


                case SshCipherConstants.AES_256_CBC:
                    return new SshCipherImpl("AES", "CBC", "NoPadding", 32, 16, 16);
                case SshCipherConstants.AES_192_CBC:
                    return new SshCipherImpl("AES", "CBC", "NoPadding", 24, 16, 16);
                case SshCipherConstants.AES_128_CBC:
                    return new SshCipherImpl("AES", "CBC", "NoPadding", 16, 16, 16);

                case SshCipherConstants.AES_256_CTR:
                    return new SshCipherImpl("AES", "CTR", "NoPadding", 32, 16, 16);
                case SshCipherConstants.AES_192_CTR:
                    return new SshCipherImpl("AES", "CTR", "NoPadding", 24, 16, 16);
                case SshCipherConstants.AES_128_CTR:
                    return new SshCipherImpl("AES", "CTR", "NoPadding", 16, 16, 16);

                case SshCipherConstants.TWOFISH_CBC:
                case SshCipherConstants.TWOFISH_256_CBC:
                    return new SshCipherImpl("Twofish", "CBC", "NoPadding", 32, 16, 16);
                case SshCipherConstants.TWOFISH_192_CBC:
                    return new SshCipherImpl("Twofish", "CBC", "NoPadding", 24, 16, 16);
                case SshCipherConstants.TWOFISH_128_CBC:
                    return new SshCipherImpl("Twofish", "CBC", "NoPadding", 16, 16, 16);

                case SshCipherConstants.TWOFISH_256_CTR:
                    return new SshCipherImpl("Twofish", "CTR", "NoPadding", 32, 16, 16);
                case SshCipherConstants.TWOFISH_192_CTR:
                    return new SshCipherImpl("Twofish", "CTR", "NoPadding", 24, 16, 16);
                case SshCipherConstants.TWOFISH_128_CTR:
                    return new SshCipherImpl("Twofish", "CTR", "NoPadding", 16, 16, 16);

                case SshCipherConstants.TRIPLE_DES_CBC:
                    return new SshCipherImpl("DESede", "CBC", "NoPadding", 24, 8, 8);
                case SshCipherConstants.TRIPLE_DES_CTR:
                    return new SshCipherImpl("DESede", "CTR", "NoPadding", 24, 8, 8);

                case SshCipherConstants.SEED_CBC_SSH_COM:
                    return new SshCipherImpl("SEED", "CBC", "NoPadding", 16, 16, 16);

                case SshCipherConstants.CAST_128_CBC:
                    return new SshCipherImpl("CAST5", "CBC", "NoPadding", 16, 8, 8);
                case SshCipherConstants.CAST_128_CTR:
                    return new SshCipherImpl("CAST5", "CTR", "NoPadding", 16, 8, 8);

                case SshCipherConstants.BLOWFISH_CBC:
                    return new SshCipherImpl("Blowfish", "CBC", "NoPadding", 16, 8, 8);
                case SshCipherConstants.BLOWFISH_CTR:
                    return new SshCipherImpl("Blowfish", "CTR", "NoPadding", 32, 8, 8);

                case SshCipherConstants.AR_C_FOUR:
                    return new RC4Cipher("RC4", "", "", 8, 16, 8, 0);
                case SshCipherConstants.AR_C_FOUR_128:
                    return new RC4Cipher("RC4", "", "", 8, 16, 8, 1536);
                case SshCipherConstants.AR_C_FOUR_256:
                    return new RC4Cipher("RC4", "", "", 8, 32, 8, 1536);

                case SshCipherConstants.NONE:
                    return new NullCipher();

                default: {
                    throw new NoSuchAlgorithmException(ERROR_ALGORITHM_NOT_FOUND + algorithm);
                }
            }
        } catch (final Exception e) {
            throw new NoSuchAlgorithmException(ERROR_ALGORITHM_NOT_FOUND + algorithm, e);
        }
    }

    @NonNull
    private static SshCipher loadCipherOrThrow(@NonNull final SshClientConfig config,
                                               @NonNull final String algorithm)
            throws NoSuchAlgorithmException {
        try {
            final String classname = config.getString(algorithm);
            if (classname == null || classname.isEmpty()) {
                throw new NoSuchAlgorithmException("No class configured for " + algorithm);
            }

            final Class<? extends SshCipher> c =
                    Class.forName(classname).asSubclass(SshCipher.class);
            final SshCipher cipher = c.getDeclaredConstructor().newInstance();
            // Check if the Cipher CAN be initialized using it's own defaults.
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                        new byte[cipher.getKeySize()],
                        new byte[cipher.getIVSize()]);

            // but always return a NEW instance (or is this overkill?)
            return (SshCipher) c.getDeclaredConstructor().newInstance();

        } catch (final Exception e) {
            throw new NoSuchAlgorithmException(ERROR_ALGORITHM_NOT_FOUND + algorithm, e);
        }
    }

    @NonNull
    public static SshMac getMac(@NonNull final SshClientConfig config,
                                @Nullable final String algorithm)
            throws NoSuchAlgorithmException {

        if (algorithm == null || algorithm.isBlank()) {
            throw new NoSuchAlgorithmException("No algorithm name given");
        }
        if (config.contains(algorithm)) {
            return loadClassOrThrow(config, algorithm, SshMac.class);
        }

        try {
            switch (algorithm) {
                case SshMacConstants.HMAC_MD_5:
                    return new SshMacImpl("HmacMD5", 16, false);

                case SshMacConstants.HMAC_MD_5_ETM_OPENSSH_COM:
                    return new SshMacImpl("HmacMD5", 16, true);

                case SshMacConstants.HMAC_MD_5_96:
                    return new SshMacImpl("HmacMD5", 12, false);

                case SshMacConstants.HMAC_MD_5_96_ETM_OPENSSH_COM:
                    return new SshMacImpl("HmacMD5", 12, true);


                case SshMacConstants.HMAC_SHA_1:
                    return new SshMacImpl("HmacSHA1", 20, false);

                case SshMacConstants.HMAC_SHA_1_ETM_OPENSSH_COM:
                    return new SshMacImpl("HmacSHA1", 20, true);

                case SshMacConstants.HMAC_SHA_1_96:
                    return new SshMacImpl("HmacSHA1", 12, false);

                case SshMacConstants.HMAC_SHA_1_96_ETM_OPENSSH_COM:
                    return new SshMacImpl("HmacSHA1", 12, true);


                case SshMacConstants.HMAC_SHA_2_256:
                case SshMacConstants.HMAC_SHA_256_2_SSH_COM:
                    return new SshMacImpl("HmacSHA256", 32, false);

                case SshMacConstants.HMAC_SHA_2_256_ETM_OPENSSH_COM:
                    return new SshMacImpl("HmacSHA256", 32, true);

                case SshMacConstants.HMAC_SHA_2_512:
                case SshMacConstants.HMAC_SHA_512_SSH_COM:
                    return new SshMacImpl("HmacSHA512", 64, false);

                case SshMacConstants.HMAC_SHA_2_512_ETM_OPENSSH_COM:
                    return new SshMacImpl("HmacSHA512", 64, true);


                case SshMacConstants.HMAC_SHA_224_SSH_COM:
                    return new SshMacImpl("HmacSHA224", 28, false);
                case SshMacConstants.HMAC_SHA_256_SSH_COM:
                    // yes, 16; see above HMAC_SHA_256_2_SSH_COM for the 32 one
                    return new SshMacImpl("HmacSHA256", 16, false);
                case SshMacConstants.HMAC_SHA_384_SSH_COM:
                    return new SshMacImpl("HmacSHA384", 48, false);

                default:
                    throw new NoSuchAlgorithmException(ERROR_ALGORITHM_NOT_FOUND + algorithm);
            }
        } catch (final Exception e) {
            throw new NoSuchAlgorithmException(ERROR_ALGORITHM_NOT_FOUND + algorithm, e);
        }
    }

    /**
     * Creates and initializes an {@link SshDeflater} instance to be
     * used for compressing outgoing data (before encryption).
     * <p>
     * We get the class name from the configuration option named with
     * the method: {@code "zlib@openssh.com"} or {@code "zlib"}.
     *
     * @param authenticated flag for delayed compression {@code "zlib@openssh.com"}
     * @param method        the compression method name as negotiated,
     *
     * @return instance, or {@code null} for no-compression
     */
    @Nullable
    public static SshDeflater getDeflater(@NonNull final SshClientConfig config,
                                          final boolean authenticated,
                                          @NonNull final String method)
            throws NoSuchAlgorithmException, IOException {

        if (KexProposal.COMPRESSION_ZLIB.equals(method) ||
                authenticated && KexProposal.COMPRESSION_ZLIB_OPENSSH_COM.equals(method)) {
            final SshDeflater instance = (SshDeflater) loadClassOrDefault(
                    config, DEFLATER_CONFIG_PREFIX + method,
                    SshDeflaterImpl.class, SshDeflater.class);

            final int level = config.getIntValue(KexProposal.COMPRESSION_LEVEL,
                                                 SshDeflater.DEFAULT_LEVEL);
            instance.init(level);
            return instance;
        }
        return null;
    }

    /**
     * Creates and initializes an {@link SshInflater} instance to be
     * used for decompressing of incoming data (after decryption).
     * <p>
     * We get the class name from the configuration option named with
     * the method: {@code "zlib@openssh.com"} and {@code "zlib"}.
     *
     * @param authenticated flag for delayed compression {@code "zlib@openssh.com"}
     * @param method        the compression method name as negotiated
     *
     * @return instance, or {@code null} for no-compression
     */
    @Nullable
    public static SshInflater getInflater(@NonNull final SshClientConfig config,
                                          final boolean authenticated,
                                          @NonNull final String method)
            throws NoSuchAlgorithmException, IOException {

        if (KexProposal.COMPRESSION_ZLIB.equals(method) ||
                authenticated && KexProposal.COMPRESSION_ZLIB_OPENSSH_COM.equals(method)) {

            final SshInflater instance = (SshInflater) loadClassOrDefault(
                    config, INFLATER_CONFIG_PREFIX + method,
                    SshInflaterImpl.class, SshInflater.class);
            instance.init();
            return instance;

        }
        return null;
    }

    /**
     * Construct the list of algorithms we can accept for public key authentication.
     *
     * @return the list; will contain at least one algorithm
     *
     * @throws NoSuchAlgorithmException if no algorithm configured/available
     */
    @NonNull
    public static List<String> getPublicKeyAcceptedAlgorithms(
            @NonNull final SshClientConfig config)
            throws NoSuchAlgorithmException {
        final List<String> all = new ArrayList<>();

        final List<String> a1 = config.getStringList(HostConfig.PUBLIC_KEY_ACCEPTED_ALGORITHMS);
        if (!a1.isEmpty()) {
            all.addAll(a1);
        }
        final List<String> a2 = config.getStringList(HostConfig.PUBLIC_KEY_ACCEPTED_KEY_TYPES);
        if (!a2.isEmpty()) {
            all.addAll(a2);
        }

        if (all.isEmpty()) {
            return all;
        }

        if (!config.getBooleanValue(PK_VALIDATE_ALGORITHM_CLASSES, true)) {
            return all.stream().distinct().collect(Collectors.toList());
        }

        final List<String> result = new ArrayList<>();
        for (final String name : all.stream().distinct().collect(Collectors.toList())) {
            try {
                final SshSignature sig = getSignature(config, name);
                sig.init(name);
                result.add(name);
            } catch (final GeneralSecurityException ignore) {
                // ignore
            }
        }

        if (result.isEmpty()) {
            throw new NoSuchAlgorithmException("No PublicKey auth algorithms available");
        }

        return result;
    }
}
