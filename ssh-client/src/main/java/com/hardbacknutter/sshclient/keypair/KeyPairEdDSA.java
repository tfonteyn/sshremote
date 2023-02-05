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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
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
import java.security.spec.X509EncodedKeySpec;
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

    private static final String ERROR_TYPE_WAS_NULL = "type was null";

    @Nullable
    private EdKeyType type;

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

        // parse from encoded... remember, this is BC, you need Java 15 to use JCE with Ed.
        final Key publicKey = keyPair.getPublic();
        setEncodedPublicKey(publicKey.getEncoded(), PublicKeyFormat.X509);

        final Key privateKey = keyPair.getPrivate();
        parsePrivateKey(privateKey.getEncoded(), Vendor.PKCS8);
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
    public static PublicKey createPublicKey(@NonNull final String curveName,
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

    @Override
    public void setEncodedPublicKey(@Nullable final byte[] encodedKey,
                                    @Nullable final PublicKeyFormat keyFormat)
            throws InvalidKeyException, NoSuchAlgorithmException,
                   InvalidKeySpecException, NoSuchProviderException {
        if (encodedKey != null && keyFormat != null) {
            switch (keyFormat) {
                case X509: {
                    Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);

                    final KeySpec keySpec = new X509EncodedKeySpec(encodedKey);
                    final KeyFactory keyFactory = KeyFactory.getInstance(type.curveName, "BC");
                    final EdDSAPublicKey key = (EdDSAPublicKey) keyFactory.generatePublic(keySpec);
                    pub_array = key.getPointEncoding();
                    break;
                }
                case OPENSSH_V1: {
                    try {
                        final Buffer buffer = new Buffer(encodedKey);
                        buffer.skipString();
                        pub_array = buffer.getString();
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
                   NoSuchAlgorithmException,
                   NoSuchProviderException {
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        Objects.requireNonNull(pub_array, "pub_array");
        return createPublicKey(type.curveName, pub_array);
    }

    @NonNull
    @Override
    protected PrivateKey getPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        Objects.requireNonNull(prv_array, "prv_array");

        final KeySpec keySpec;
        try {
            // create as an ASN1 object, so we can create the PKCS8 keySpec from it.
            final PrivateKeyInfo keyInfo = new PrivateKeyInfo(
                    new AlgorithmIdentifier(type.keyOid),
                    new DEROctetString(prv_array));
            keySpec = new PKCS8EncodedKeySpec(keyInfo.getEncoded());

        } catch (final IOException e) {
            throw new InvalidKeySpecException(e);
        }

        final KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", "BC");
        return keyFactory.generatePrivate(keySpec);
    }

    @NonNull
    @Override
    public byte[] getSshEncodedPublicKey() {
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);
        return wrapPublicKey(type.hostKeyAlgorithm, pub_array);
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
        Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);

        // concat the private key + the public key
        final byte[] encodedKeys = new byte[prv_array.length + pub_array.length];
        System.arraycopy(prv_array, 0, encodedKeys, 0, prv_array.length);
        System.arraycopy(pub_array, 0, encodedKeys, prv_array.length, pub_array.length);
        return new Buffer()
                .putString(type.hostKeyAlgorithm)
                .putString(pub_array)
                .putString(encodedKeys)
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
                    prv_array = buffer.getString();
                    break;
                }

                case OPENSSH_V1: {
                    Objects.requireNonNull(type, ERROR_TYPE_WAS_NULL);

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

                case PKCS8: {
                    // id_Ed25519
                    // Sequence                              ==> 'root'
                    //     Integer(1)                        ==> version
                    //     Sequence
                    //         ObjectIdentifier(1.3.101.112) ==> EdECObjectIdentifiers.id_Ed25519
                    //     DER Octet String[59]              ==> 'privateKeyBlob'
                    //         0439580...
                    //     Tagged [1] IMPLICIT
                    //         DER Octet String[58]
                    //             00123

                    // id_Ed448
                    // Sequence                              ==> 'root'
                    //     Integer(1)                        ==> version
                    //     Sequence
                    //         ObjectIdentifier(1.3.101.113) ==> EdECObjectIdentifiers.id_Ed448
                    //     DER Octet String[59]              ==> 'privateKeyBlob'
                    //         0439580...
                    //     Tagged [1] IMPLICIT
                    //         DER Octet String[58]
                    //             00123
                    final ASN1Sequence root;
                    try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                        root = ASN1Sequence.getInstance(stream.readObject());
                    }
                    //final ASN1Integer version = ASN1Integer.getInstance(root.getObjectAt(0));
                    final ASN1Sequence subSeq = ASN1Sequence.getInstance(root.getObjectAt(1));
                    final ASN1OctetString privateKeyBlob = ASN1OctetString.getInstance(
                            root.getObjectAt(2));

                    final ASN1ObjectIdentifier prvKeyAlgOID = ASN1ObjectIdentifier.getInstance(
                            subSeq.getObjectAt(0));
                    type = EdKeyType.getByOid(prvKeyAlgOID);

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
        public Builder setHostKeyAlgorithm(@NonNull final String hostKeyAlgorithm)
                throws NoSuchAlgorithmException {
            this.type = EdKeyType.getByHostKeyAlgorithm(hostKeyAlgorithm);
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
            return new KeyPairEdDSA(config, this);
        }
    }
}
