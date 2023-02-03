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
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.sec.ECPrivateKey;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Objects;

/**
 * The KeyPair implementation for an ECDSA key pair.
 * <p>
 * Note that we use a mix of the JDK classes for normal use
 * and Bouncy Castle for ASN1 encoding/decoding.
 *
 * <pre>
 *     ECPrivateKey ::= SEQUENCE {
 *         version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *         privateKey     OCTET STRING,
 *         parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *         publicKey  [1] BIT STRING OPTIONAL
 *         }
 * </pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5915">
 * RFC 5915  Elliptic Curve Private Key Structure</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5480">
 * RFC 5480 Elliptic Curve Cryptography Subject Public Key Information</a>
 */
public class KeyPairECDSA
        extends KeyPairBase {

    /**
     * TODO: check WHEN/IF the type could be null
     * This error should only occur when the pair is used as a delegate
     * (e.g. {@link KeyPairOpenSSHv1} in which case calling the related method is a bug.
     */
    private static final String ERROR_TYPE_WAS_NULL = "type was null; using a delegate?";

    @Nullable
    private ECKeyType type;

    /** private key value. */
    @Nullable
    private BigInteger s;
    /** The public point W. */
    @Nullable
    private ECPoint w;

    /**
     * Constructor.
     *
     * @param builder to use
     */
    private KeyPairECDSA(@NonNull final SshClientConfig config,
                         @NonNull final Builder builder)
            throws GeneralSecurityException {
        super(config, builder.privateKeyBlob, builder.privateKeyFormat,
              builder.encrypted, builder.decryptor);

        this.type = builder.type;
        this.s = builder.s;
        this.w = builder.w;

        parse();
    }

    /**
     * Generate a <strong>new</strong> KeyPair with the given keySize.
     */
    public KeyPairECDSA(@NonNull final SshClientConfig config,
                        final int keySize)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        super(config);

        this.type = ECKeyType.getByKeySize(keySize);

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        final AlgorithmParameterSpec params = new ECGenParameterSpec(type.curveName);
        keyPairGenerator.initialize(params);

        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        w = ((java.security.interfaces.ECPublicKey) keyPair.getPublic()).getW();
        s = ((java.security.interfaces.ECPrivateKey) keyPair.getPrivate()).getS();
    }

    /**
     * Construct the PrivateKey based on the components.
     *
     * @return key
     */
    @SuppressWarnings("WeakerAccess")
    @NonNull
    public static PrivateKey generatePrivate(@NonNull final String curveName,
                                             @NonNull final BigInteger s)
            throws InvalidKeySpecException, NoSuchAlgorithmException,
                   InvalidParameterSpecException {

        final AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC");
        algParams.init(new ECGenParameterSpec(curveName));
        final ECParameterSpec param = algParams.getParameterSpec(ECParameterSpec.class);

        final KeySpec keySpec = new ECPrivateKeySpec(s, param);
        final KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Construct the PublicKey based on the components.
     *
     * @return key
     */
    @NonNull
    public static PublicKey generatePublic(@NonNull final String curveName,
                                           @NonNull final ECPoint w)
            throws InvalidKeySpecException, NoSuchAlgorithmException,
                   InvalidParameterSpecException {

        final AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC");
        algParams.init(new ECGenParameterSpec(curveName));
        final ECParameterSpec param = algParams.getParameterSpec(ECParameterSpec.class);

        final KeySpec keySpec = new ECPublicKeySpec(w, param);
        final KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    @NonNull
    @Override
    public String getHostKeyAlgorithm() {
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        return type.hostKeyAlgorithm;
    }

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
        if (w == null) {
            return null;
        }

        // sanity check for the type.
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        return wrapPublicKey(type.hostKeyAlgorithm.getBytes(StandardCharsets.UTF_8),
                             type.nistName.getBytes(StandardCharsets.UTF_8),
                             type.encodePoint(w));
    }

    @Override
    public void setSshPublicKeyBlob(@Nullable final byte[] publicKeyBlob) {
        super.setSshPublicKeyBlob(publicKeyBlob);

//        if (publicKeyBlob != null) {
//            if (privateKeyFormat == Vendor.ASN1) {
//                try {
//                    final Buffer buffer = new Buffer(publicKeyBlob);
//                    buffer.skipString(/* type.hostKeyAlgorithm */);
//                    buffer.skipString(/* type.nistName */);
//                    w = ECKeyType.decodePoint(buffer.getString());
//                } catch (@NonNull final IOException e) {
//                    if (config.getLogger().isEnabled(Logger.DEBUG)) {
//                        config.getLogger().log(Logger.DEBUG, e, () -> DEBUG_KEY_PARSING_FAILED);
//                    }
//                }
//            }
//        }
    }

    @NonNull
    public byte[] getSignature(@NonNull final byte[] data,
                               @NonNull final String algorithm)
            throws GeneralSecurityException {

        final SshSignature sig = ImplementationFactory.getSignature(config, algorithm);
        sig.init(algorithm);

        //noinspection ConstantConditions
        sig.initSign(generatePrivate(type.curveName, s));
        sig.update(data);
        final byte[] signature_blob = sig.sign();
        return wrapSignature(algorithm, signature_blob);
    }

    @NonNull
    @Override
    public SshSignature getVerifier(@NonNull final String algorithm)
            throws GeneralSecurityException, IOException {
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);

        final SshSignature sig = ImplementationFactory.getSignature(config, algorithm);
        sig.init(algorithm);

        final byte[] publicKeyBlob = this.getSshPublicKeyBlob();
        if (w == null && publicKeyBlob != null) {
            final Buffer buffer = new Buffer(publicKeyBlob);
            buffer.skipString(/* hostKeyAlgorithmName */);
            buffer.skipString(/* nistName */);
            w = ECKeyType.decodePoint(buffer.getString());
        }

        Objects.requireNonNull(w);
        sig.initVerify(generatePublic(type.curveName, w));
        return sig;
    }

    @NonNull
    @Override
    public byte[] forSSHAgent()
            throws KeyManagementException {
        if (isPrivateKeyEncrypted()) {
            throw new KeyManagementException("key is encrypted");
        }
        //noinspection ConstantConditions
        return new Buffer()
                .putString((type.hostKeyAlgorithm))
                .putString(type.nistName)
                .putString(type.encodePoint(w))
                .putMPInt(s)
                .putString(getPublicKeyComment())
                .getPayload();
    }

    @Override
    void parsePrivateKey(@NonNull final byte[] encodedKey,
                         @NonNull final Vendor keyFormat)
            throws GeneralSecurityException {

        try {
            switch (keyFormat) {
                case PUTTY3:
                case PUTTY2: {
                    final Buffer buffer = new Buffer(encodedKey);
                    s = buffer.getBigInteger();
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
                    type = ECKeyType.getByHostKeyAlgorithm(buffer.getJString());
                    buffer.skipString(/* nist name*/);

                    w = ECKeyType.decodePoint(buffer.getString());
                    s = buffer.getBigInteger();
                    setPublicKeyComment(buffer.getJString());

                    break;
                }

                case ASN1: {
                    final ECPrivateKey key;
                    try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                        key = ECPrivateKey.getInstance(stream.readObject());
                    }
                    w = ECKeyType.decodePoint(key.getPublicKey().getBytes());
                    s = key.getKey();

                    type = ECKeyType.getByECPoint(w);
                    break;
                }
                default:
                    throw new UnsupportedKeyBlobEncodingException(String.valueOf(keyFormat));

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

    @NonNull
    @Override
    public byte[] getEncoded()
            throws InvalidKeyException, IOException {
        if (type == null || s == null) {
            throw new InvalidKeyException("No key data");
        }

        if (w != null) {
            return new ECPrivateKey(type.keySize, s,
                                    new DERBitString(type.encodePoint(w)),
                                    type.keyOid)
                    .getEncoded();
        } else {
            return new ECPrivateKey(type.keySize, s, null, null)
                    .getEncoded();
        }
    }

    public static class Builder {

        @NonNull
        final SshClientConfig config;
        @Nullable
        private ECKeyType type;

        @Nullable
        private ECPoint w;

        @Nullable
        private BigInteger s;
        private byte[] privateKeyBlob;
        private Vendor privateKeyFormat;
        private boolean encrypted;
        @Nullable
        private PKDecryptor decryptor;

        public Builder(@NonNull final SshClientConfig config) {
            this.config = config;
        }

        @NonNull
        public Builder setType(@NonNull final ECKeyType type) {
            this.type = type;
            return this;
        }

        @NonNull
        public Builder setPoint(@NonNull final ECPoint w) {
            this.w = w;
            return this;
        }

        @NonNull
        public Builder setS(@NonNull final BigInteger s) {
            this.s = s;
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
            this.s = new BigInteger(1, this.privateKeyBlob);
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
            return new KeyPairECDSA(config, this);
        }
    }
}
