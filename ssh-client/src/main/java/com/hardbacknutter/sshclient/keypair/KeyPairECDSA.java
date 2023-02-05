package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.utils.Buffer;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
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
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
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
        // JCE provides direct access; no need to use getEncoded() + parse()
        w = ((java.security.interfaces.ECPublicKey) keyPair.getPublic()).getW();
        s = ((java.security.interfaces.ECPrivateKey) keyPair.getPrivate()).getS();
    }

    /**
     * Construct the PublicKey based on the components.
     *
     * @return key
     */
    @NonNull
    public static PublicKey createPublicKey(@NonNull final String curveName,
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

    @Override
    public void setEncodedPublicKey(@Nullable final byte[] encodedKey,
                                    @Nullable final PublicKeyFormat keyFormat)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (encodedKey != null && keyFormat != null) {
            switch (keyFormat) {
                case X509: {
                    final KeySpec keySpec = new X509EncodedKeySpec(encodedKey);
                    final KeyFactory keyFactory = KeyFactory.getInstance("EC");
                    final ECPublicKey publicKey =
                            (ECPublicKey) keyFactory.generatePublic(keySpec);
                    w = publicKey.getW();
                    break;
                }
                case OPENSSH_V1: {
                    try {
                        final Buffer buffer = new Buffer(encodedKey);
                        buffer.skipString(/* HostKeyAlgorithm */);
                        buffer.skipString(/* nistName */);
                        w = ECKeyType.decodePoint(buffer.getString());
                    } catch (@NonNull final IOException e) {
                        throw new InvalidKeyException(e);
                    }
                    break;
                }
                default:
                    throw new InvalidKeyException(String.valueOf(keyFormat));
            }
        }
    }

    @Override
    @NonNull
    public PublicKey getPublicKey()
            throws InvalidKeySpecException,
                   InvalidParameterSpecException,
                   NoSuchAlgorithmException {
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        Objects.requireNonNull(w, "w");
        return createPublicKey(type.curveName, w);
    }

    @NonNull
    @Override
    protected PrivateKey getPrivateKey()
            throws InvalidKeySpecException,
                   InvalidParameterSpecException,
                   NoSuchAlgorithmException {
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        Objects.requireNonNull(s, "s");

        final AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC");
        algParams.init(new ECGenParameterSpec(type.curveName));
        final ECParameterSpec param = algParams.getParameterSpec(ECParameterSpec.class);

        final KeySpec keySpec = new ECPrivateKeySpec(s, param);
        final KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }

    @NonNull
    @Override
    public byte[] getSshEncodedPublicKey() {
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        Objects.requireNonNull(w, "w");
        return wrapPublicKey(type.hostKeyAlgorithm,
                             type.nistName.getBytes(StandardCharsets.UTF_8),
                             type.encodePoint(w));
    }

    @NonNull
    @Override
    public byte[] forSSHAgent()
            throws KeyManagementException {
        if (isPrivateKeyEncrypted()) {
            throw new KeyManagementException("key is encrypted");
        }
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        Objects.requireNonNull(w, "w");
        Objects.requireNonNull(s, "s");

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
                case PUTTY_V3:
                case PUTTY_V2: {
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

                case PKCS8: {
                    // Sequence                                         ==> 'root'
                    //     Integer(0)                                   ==> version
                    //     Sequence                                     ==> 'subSeq'
                    //         ObjectIdentifier(1.2.840.10045.2.1)      ==> 'prvKeyAlgOID'
                    //         ObjectIdentifier(1.2.840.10045.3.1.7)    ==> curve
                    //     DER Octet String[109]                        ==> 'privateKey'
                    //         306b02010...
                    final ASN1Sequence root;
                    try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                        root = ASN1Sequence.getInstance(stream.readObject());
                    }
                    // final ASN1Integer version = ASN1Integer.getInstance(root.getObjectAt(0));
                    final ASN1Sequence subSeq = ASN1Sequence.getInstance(root.getObjectAt(1));
                    final ASN1OctetString privateKeyBlob = ASN1OctetString.getInstance(
                            root.getObjectAt(2));

                    // final ASN1ObjectIdentifier prvKeyAlgOID = ASN1ObjectIdentifier.getInstance(
                    //        subSeq.getObjectAt(0));
                    final ASN1ObjectIdentifier primeOid = ASN1ObjectIdentifier.getInstance(
                            subSeq.getObjectAt(1));
                    type = ECKeyType.getByOid(primeOid);

                    parsePrivateKey(privateKeyBlob.getOctets(), Vendor.ASN1);
                    return;
                }
                default:
                    throw new UnsupportedKeyBlobEncodingException(String.valueOf(keyFormat));

            }
        } catch (@NonNull final GeneralSecurityException e) {
            // We have an actual error
            throw e;

        } catch (@NonNull final Exception ignore) {
            if (config.getLogger().isEnabled(Logger.DEBUG)) {
                config.getLogger().log(Logger.DEBUG, () -> DEBUG_KEY_PARSING_FAILED);
            }
            // failed due to a key format decoding problem
            setPrivateKeyEncrypted(true);
            return;
        }

        setPrivateKeyEncrypted(false);
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
        public Builder setHostKeyAlgorithm(@NonNull final String hostKeyAlgorithm)
                throws NoSuchAlgorithmException {
            this.type = ECKeyType.getByHostKeyAlgorithm(hostKeyAlgorithm);
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
         * @param privateKeyBlob The encoded private key
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
            return new KeyPairECDSA(config, this);
        }
    }
}
