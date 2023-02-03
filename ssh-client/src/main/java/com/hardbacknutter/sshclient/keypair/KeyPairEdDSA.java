package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.signature.SshSignature;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * Using Bouncy castle; using SunEC requires Java 15
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8032/">
 * RFC 8032 Edwards-Curve Digital Signature Algorithm (EdDSA)</a>
 */
public class KeyPairEdDSA
        extends KeyPairBase {

    /**
     * TODO: check WHEN/IF the type could be null
     * This error should only occur when the pair is used as a delegate
     * (e.g. {@link KeyPairOpenSSHv1} in which case calling the related method is a bug.
     */
    private static final String ERROR_TYPE_WAS_NULL = "type was null; using a delegate?";

    @Nullable
    private final EdKeyType type;

    @Nullable
    private byte[] prv_array;

    /** the length will be {@link EdKeyType#keySize}. */
    @Nullable
    private byte[] pub_array;

    /**
     * Constructor.
     *
     * @param builder to use
     */
    private KeyPairEdDSA(@NonNull final SshClientConfig config,
                         @NonNull final Builder builder)
            throws GeneralSecurityException {
        super(config, builder.privateKeyBlob, builder.privateKeyFormat,
              builder.encrypted, builder.decryptor);

        this.type = builder.type;
        this.prv_array = builder.prv_array;
        this.pub_array = builder.pub_array;

        parse();
    }

    /**
     * Generate a <strong>new</strong> KeyPair with the given curve.
     *
     * @param curveName "Ed25519" or "Ed448"
     */
    public KeyPairEdDSA(@NonNull final SshClientConfig config,
                        @NonNull final String curveName)
            throws GeneralSecurityException {
        super(config);

        this.type = EdKeyType.getByCurveName(curveName);

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(type.curveName, "BC");
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        pub_array = type.extractPubArray((EdDSAPublicKey) keyPair.getPublic());

        @Nullable final byte[] encodedPrivateKeyBlob = keyPair.getPrivate().getEncoded();
        // sanity check for null
        if (encodedPrivateKeyBlob != null) {
            parse(encodedPrivateKeyBlob, Vendor.ASN1);
        }
    }

    /**
     * Construct the PrivateKey based on the components.
     *
     * @return key
     */
    @SuppressWarnings("WeakerAccess")
    @NonNull
    public static PrivateKey generatePrivate(@NonNull final EdKeyType edType,
                                             @NonNull final byte[] bytes)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

        final KeySpec keySpec;
        try {
            // create as an ASN1 object, so we can read the keySpec from it.
            final PrivateKeyInfo keyInfo = new PrivateKeyInfo(
                    new AlgorithmIdentifier(edType.keyOid),
                    new DEROctetString(bytes));
            keySpec = new PKCS8EncodedKeySpec(keyInfo.getEncoded());

        } catch (final IOException e) {
            throw new InvalidKeySpecException(e);
        }

        final KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", "BC");
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Construct the PublicKey based on the components.
     *
     * @param curveName "Ed25519" or "Ed448"
     * @param rawKey    the {@link EdKeyType#keySize} byte long raw public key data
     *
     * @return key
     */
    @NonNull
    public static PublicKey generatePublic(@NonNull final String curveName,
                                           @NonNull final byte[] rawKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

        final KeySpec keySpec = new RawEncodedKeySpec(rawKey);

        final KeyFactory keyFactory = KeyFactory.getInstance(curveName, "BC");
        return keyFactory.generatePublic(keySpec);
    }

    @NonNull
    @Override
    public String getHostKeyAlgorithm() {
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        return type.hostKeyAlgorithm;
    }

    /**
     * EdDSA uses the length {@link EdKeyType#keySize} of the key.
     *
     * @return key size in bytes
     */
    @Override
    public int getKeySize() {
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        return type.keySize;
    }

    @Nullable
    @Override
    public byte[] getSshPublicKeyBlob()
            throws GeneralSecurityException {
        final byte[] keyBlob = super.getSshPublicKeyBlob();
        // If we have a pre-build encoded public key, use it.
        if (keyBlob != null) {
            return keyBlob;
        }

        // Do we have what we need to construct the encoded public key?
        if (pub_array == null) {
            return null;
        }

        // sanity check for the type.
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        return wrapPublicKey(type.hostKeyAlgorithm.getBytes(StandardCharsets.UTF_8), pub_array);
    }

    @Override
    public void setSshPublicKeyBlob(@Nullable final byte[] publicKeyBlob) {
        super.setSshPublicKeyBlob(publicKeyBlob);

        if (publicKeyBlob != null) {
            Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
            type.stripPrefix(publicKeyBlob).ifPresent(key -> pub_array = key);
        }
    }

    @Override
    @NonNull
    public byte[] getSignature(@NonNull final byte[] data,
                               @NonNull final String algorithm)
            throws GeneralSecurityException {

        final SshSignature sig = ImplementationFactory.getSignature(config, algorithm);
        sig.init(algorithm);

        //noinspection ConstantConditions
        sig.initSign(generatePrivate(type, prv_array));
        sig.update(data);
        final byte[] signature_blob = sig.sign();
        return wrapSignature(algorithm, signature_blob);
    }

    @Override
    @NonNull
    public SshSignature getVerifier(@NonNull final String algorithm)
            throws GeneralSecurityException, IOException {

        final SshSignature sig = ImplementationFactory.getSignature(config, algorithm);
        sig.init(algorithm);


        final byte[] publicKeyBlob = getSshPublicKeyBlob();
        if (pub_array == null && publicKeyBlob != null) {
            final Buffer buffer = new Buffer(publicKeyBlob);
            buffer.skipString();
            pub_array = buffer.getString();
        }

        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        Objects.requireNonNull(pub_array, "pub_array");
        final PublicKey publicKey = generatePublic(type.curveName, pub_array);
        sig.initVerify(publicKey);
        return sig;
    }

    @Override
    @NonNull
    public byte[] forSSHAgent()
            throws KeyManagementException {
        if (isPrivateKeyEncrypted()) {
            throw new KeyManagementException("Key is encrypted");
        }
        if (prv_array == null || pub_array == null) {
            throw new KeyManagementException("pub/prv arrays are not set");
        }

        // concat the private key + the public key
        final byte[] encodedKeys = new byte[prv_array.length + pub_array.length];
        System.arraycopy(prv_array, 0, encodedKeys, 0, prv_array.length);
        System.arraycopy(pub_array, 0, encodedKeys, prv_array.length, pub_array.length);

        //noinspection ConstantConditions
        return new Buffer()
                .putString(type.hostKeyAlgorithm)
                .putString(pub_array)
                .putString(encodedKeys)
                .putString(getPublicKeyComment())
                .getPayload();
    }

    @Override
    void parse(@NonNull final byte[] encodedKey,
               @NonNull final Vendor keyFormat)
            throws GeneralSecurityException {

        try {
            switch (keyFormat) {
                case PUTTY3:
                case PUTTY2: {
                    final Buffer buffer = new Buffer(encodedKey);
                    prv_array = buffer.getString();
                    break;
                }

                case OPENSSH_V1: {
                    final Buffer buffer = new Buffer(encodedKey);
                    // 64-bit dummy checksum  # a random 32-bit int, repeated
                    final int checkInt1 = buffer.getInt();
                    final int checkInt2 = buffer.getInt();
                    if (checkInt1 != checkInt2) {
                        throw new InvalidKeyException("checksum failed");
                    }
                    buffer.skipString(/* hostKeyAlgorithmName */);

                    pub_array = buffer.getString();

                    // OpenSSH stores private key in first half of string and duplicate copy
                    // of public key in second half of string
                    final byte[] tmp = buffer.getString(); // secret key (private key + public key)
                    // extract the first half
                    //noinspection ConstantConditions
                    prv_array = Arrays.copyOf(tmp, type.keySize);

                    setPublicKeyComment(buffer.getJString());
                    break;
                }

                case ASN1: {
                    final ASN1OctetString root;
                    try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                        root = ASN1OctetString.getInstance(stream.readObject());
                    }
                    prv_array = root.getOctets();
                    break;
                }
                default:
                    throw new UnsupportedEncodingException(String.valueOf(keyFormat));

            }
        } catch (@NonNull final GeneralSecurityException e) {
            // We have an actual error
            throw e;

        } catch (@NonNull final Exception e) {
            if (config.getLogger().isEnabled(Logger.DEBUG)) {
                config.getLogger().log(Logger.DEBUG, e, () -> DEBUG_KEY_PARSING_FAILED);
            }
            // failed due to a key format decoding problem
            setPrivateKeyEncrypted(true);
            return;
        }

        setPrivateKeyEncrypted(false);
    }

    @Override
    public void dispose() {
        super.dispose();
        if (prv_array != null) {
            Arrays.fill(prv_array, (byte) 0);
        }
    }

    public static class Builder {

        @NonNull
        final SshClientConfig config;
        @Nullable
        private EdKeyType type;
        @Nullable
        private byte[] prv_array;
        @Nullable
        private byte[] pub_array;
        private byte[] privateKeyBlob;
        private Vendor privateKeyFormat;
        private boolean encrypted;
        @Nullable
        private PKDecryptor decryptor;

        public Builder(@NonNull final SshClientConfig config)
                throws NoSuchAlgorithmException {
            this.config = config;
        }

        @NonNull
        public Builder setType(@NonNull final EdKeyType type) {
            this.type = type;
            return this;
        }

        /**
         * Set the raw 32 byte private key blob.
         *
         * @throws InvalidKeyException if the length was not 32
         */
        @NonNull
        public Builder setPrvArray(@NonNull final byte[] bytes) throws InvalidKeyException {
            Objects.requireNonNull(type, "Set type first");
            if (bytes.length != type.keySize) {
                throw new InvalidKeyException("prv_array length must be " + type.keySize
                                                      + ", but was " + bytes.length);
            }

            this.prv_array = bytes;
            return this;
        }

        /**
         * Set the raw 32 byte public key blob.
         *
         * @throws InvalidKeyException if the length was not 32
         */
        @NonNull
        public Builder setPubArray(@NonNull final byte[] bytes) throws InvalidKeyException {
            Objects.requireNonNull(type, "Set type first");
            if (bytes.length != type.keySize) {
                throw new InvalidKeyException("pub_array length must be " + type.keySize
                                                      + ", but was " + bytes.length);
            }
            this.pub_array = bytes;
            return this;
        }

        /**
         * Set the private key blob.
         *
         * @param privateKeyBlob The byte[] with the private key
         */
        @NonNull
        public Builder setPrivateKey(@NonNull final byte[] privateKeyBlob) {
            this.privateKeyBlob = privateKeyBlob;
            return this;
        }

        /**
         * Set the encoding/format for the private key blob.
         *
         * @param format The vendor specific format of the private key
         *               This is independent from the encryption state.
         */
        @NonNull
        public Builder setFormat(@NonNull final Vendor format) {
            this.privateKeyFormat = format;
            return this;
        }

        /**
         * Set the optional decryptor to use if the key is encrypted.
         *
         * @param decryptor (optional) The vendor specific decryptor
         */
        @NonNull
        public Builder setDecryptor(@Nullable final PKDecryptor decryptor) {
            this.decryptor = decryptor;
            this.encrypted = decryptor != null;
            return this;
        }

        @NonNull
        public SshKeyPair build()
                throws GeneralSecurityException {
            return new KeyPairEdDSA(config, this);
        }
    }
}
