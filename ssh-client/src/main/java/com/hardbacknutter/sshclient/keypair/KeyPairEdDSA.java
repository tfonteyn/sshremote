package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

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

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDF;
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

/**
 * Using Bouncy castle; using SunEC requires Java 15
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8032/">
 *         RFC 8032 Edwards-Curve Digital Signature Algorithm (EdDSA)</a>
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
        super(config,
              Objects.requireNonNull(builder.privateKeyBlob),
              Objects.requireNonNull(builder.privateKeyEncoding),
              builder.encrypted,
              builder.decryptor);

        parsePublicKey(builder.publicKeyBlob, builder.publicKeyEncoding);
        parsePrivateKey();
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
        parsePublicKey(publicKey.getEncoded(), PublicKeyEncoding.X509);

        final Key privateKey = keyPair.getPrivate();
        parsePrivateKey(privateKey.getEncoded(), PrivateKeyEncoding.PKCS8);
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
    public byte[] toSshAgentEncodedKeyPair()
            throws KeyManagementException {
        if (isEncrypted()) {
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

    /**
     * Decode the public key blob into the components.
     *
     * @param encodedKey the key data.
     * @param encoding   the encoding format
     */
    private void parsePublicKey(@Nullable final byte[] encodedKey,
                                @Nullable final PublicKeyEncoding encoding)
            throws NoSuchAlgorithmException,
                   NoSuchProviderException,
                   InvalidKeySpecException,
                   InvalidKeyException {
        if (encodedKey != null && encoding != null) {
            switch (encoding) {
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
                        type = EdKeyType.getByHostKeyAlgorithm(buffer.getJString());
                        pub_array = buffer.getString();
                    } catch (@NonNull final IOException e) {
                        throw new InvalidKeyException(e);
                    }
                    break;
                }
                default:
                    throw new InvalidKeyException(String.valueOf(encoding));
            }
        }
    }

    @Override
    void parsePrivateKey(@NonNull final byte[] encodedKey,
                         @NonNull final PrivateKeyEncoding encoding)
            throws GeneralSecurityException {

        try {
            switch (encoding) {
                case PUTTY_V3:
                case PUTTY_V2: {
                    final Buffer buffer = new Buffer(encodedKey);
                    prv_array = buffer.getString();
                    // type and pub_array are set during public key parsing
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
                    type = EdKeyType.getByHostKeyAlgorithm(buffer.getJString());
                    pub_array = buffer.getString();
                    // OpenSSH stores private key in first half of string and duplicate copy
                    // of public key in second half of string
                    prv_array = Arrays.copyOf(buffer.getString(), type.keySize);
                    setPublicKeyComment(buffer.getJString());
                    break;
                }

                case SSH_AGENT: {
                    final Buffer buffer = new Buffer(encodedKey);
                    type = EdKeyType.getByHostKeyAlgorithm(buffer.getJString());
                    pub_array = buffer.getString();
                    // OpenSSH stores private key in first half of string and duplicate copy
                    // of public key in second half of string. Hence only copy one half.
                    prv_array = Arrays.copyOf(buffer.getString(), type.keySize);
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
                    final ASN1OctetString embeddedPrvKeyBlob = ASN1OctetString.getInstance(
                            root.getObjectAt(2));

                    final ASN1ObjectIdentifier prvKeyAlgOID = ASN1ObjectIdentifier.getInstance(
                            subSeq.getObjectAt(0));
                    type = EdKeyType.getByOid(prvKeyAlgOID);

                    // REPLACE the blob. THE ASN1Sequence IS NOW INVALID.
                    privateKeyBlob = embeddedPrvKeyBlob.getOctets();
                    privateKeyEncoding = PrivateKeyEncoding.ASN1;
                    // parse the new/embedded blob
                    parsePrivateKey(privateKeyBlob, privateKeyEncoding);
                    return;
                }
                default:
                    throw new UnsupportedKeyBlobEncodingException(encoding);

            }
        } catch (@NonNull final GeneralSecurityException e) {
            // We have an actual error
            throw e;

        } catch (@NonNull final Exception ignore) {
            config.getLogger().log(Logger.DEBUG, () -> DEBUG_KEY_PARSING_FAILED);

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

    public static class Builder
            implements KeyPairBuilder {

        @NonNull
        final SshClientConfig config;
        @Nullable
        private byte[] publicKeyBlob;
        @Nullable
        private PublicKeyEncoding publicKeyEncoding;
        @Nullable
        private byte[] privateKeyBlob;
        @Nullable
        private PrivateKeyEncoding privateKeyEncoding;
        private boolean encrypted;
        @Nullable
        private PBKDF decryptor;

        public Builder(@NonNull final SshClientConfig config)
                throws NoSuchAlgorithmException {
            this.config = config;
        }

        @Override
        @NonNull
        public Builder setPrivateKey(@NonNull final byte[] privateKeyBlob,
                                     @NonNull final PrivateKeyEncoding encoding) {
            this.privateKeyBlob = privateKeyBlob;
            this.privateKeyEncoding = encoding;
            return this;
        }

        @Override
        @NonNull
        public Builder setPublicKey(@Nullable final byte[] publicKeyBlob,
                                    @Nullable final PublicKeyEncoding encoding) {
            this.publicKeyBlob = publicKeyBlob;
            this.publicKeyEncoding = encoding;
            return this;
        }

        @Override
        @NonNull
        public Builder setDecryptor(@Nullable final PBKDF decryptor) {
            this.decryptor = decryptor;
            this.encrypted = decryptor != null;
            return this;
        }

        @Override
        @NonNull
        public SshKeyPair build()
                throws GeneralSecurityException {
            return new KeyPairEdDSA(config, this);
        }
    }
}
