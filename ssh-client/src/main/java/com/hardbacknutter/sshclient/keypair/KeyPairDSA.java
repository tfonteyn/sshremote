package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDF;
import com.hardbacknutter.sshclient.utils.Buffer;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * @see <a href="https://www.rfc-editor.org/rfc/rfc5480#appendix-A">rfc5480 ASN.1</a>
 */
public class KeyPairDSA
        extends KeyPairBase {

    private static final String serverHostKeyAlgorithm = HostKeyAlgorithm.SSH_DSS;

    /** the value of the private key. */
    @Nullable
    private BigInteger x;
    /** the value of the public key. */
    @Nullable
    private BigInteger y;
    /** the private key prime. */
    @Nullable
    private BigInteger p;
    /** the private key subprime. */
    @Nullable
    private BigInteger q;
    /** the private key base. */
    @Nullable
    private BigInteger g;

    private int keySize = 1024;

    /**
     * Constructor.
     *
     * @param builder to use
     */
    private KeyPairDSA(@NonNull final SshClientConfig config,
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
     * Generate a <strong>new</strong> KeyPair of the given key size.
     */
    public KeyPairDSA(@NonNull final SshClientConfig config)
            throws NoSuchAlgorithmException {
        super(config);

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(this.keySize);

        final KeyPair keyPairGen = keyPairGenerator.generateKeyPair();
        final DSAPrivateKey prvKey = (DSAPrivateKey) keyPairGen.getPrivate();
        final DSAPublicKey pubKey = (DSAPublicKey) keyPairGen.getPublic();

        this.y = pubKey.getY();
        this.x = prvKey.getX();

        final DSAParams params = prvKey.getParams();
        this.p = params.getP();
        this.q = params.getQ();
        this.g = params.getG();
    }

    /**
     * Construct the PublicKey based on the components.
     *
     * @return key
     */
    @NonNull
    public static PublicKey createPublicKey(@NonNull final BigInteger y,
                                            @NonNull final BigInteger p,
                                            @NonNull final BigInteger q,
                                            @NonNull final BigInteger g)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        final KeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
        final KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        return keyFactory.generatePublic(keySpec);
    }

    @NonNull
    @Override
    public String getHostKeyAlgorithm() {
        return serverHostKeyAlgorithm;
    }

    @Override
    public int getKeySize() {
        return keySize;
    }

    @Override
    @NonNull
    public PublicKey getPublicKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        Objects.requireNonNull(y, "y");
        Objects.requireNonNull(p, "p");
        Objects.requireNonNull(q, "q");
        Objects.requireNonNull(g, "g");
        return createPublicKey(y, p, q, g);
    }

    @NonNull
    @Override
    protected PrivateKey getPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        Objects.requireNonNull(x, "x");
        Objects.requireNonNull(p, "p");
        Objects.requireNonNull(q, "q");
        Objects.requireNonNull(g, "g");

        final KeySpec keySpec = new DSAPrivateKeySpec(x, p, q, g);
        final KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        return keyFactory.generatePrivate(keySpec);
    }

    @NonNull
    @Override
    public byte[] getSshEncodedPublicKey() {
        Objects.requireNonNull(y, "y");
        Objects.requireNonNull(p, "p");
        Objects.requireNonNull(q, "q");
        Objects.requireNonNull(g, "g");
        return wrapPublicKey(serverHostKeyAlgorithm,
                             p.toByteArray(),
                             q.toByteArray(),
                             g.toByteArray(),
                             y.toByteArray());
    }

    @NonNull
    @Override
    public byte[] toSshAgentEncodedKeyPair()
            throws KeyManagementException {
        if (isEncrypted()) {
            throw new KeyManagementException("key is encrypted.");
        }
        Objects.requireNonNull(x, "x");
        Objects.requireNonNull(y, "y");
        Objects.requireNonNull(p, "p");
        Objects.requireNonNull(q, "q");
        Objects.requireNonNull(g, "g");

        return new Buffer()
                .putString(serverHostKeyAlgorithm)
                .putMPInt(p)
                .putMPInt(q)
                .putMPInt(g)
                .putMPInt(y)
                .putMPInt(x)
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
                   InvalidKeySpecException,
                   InvalidKeyException {
        if (encodedKey != null && encoding != null) {
            switch (encoding) {
                case X509: {
                    final KeySpec keySpec = new X509EncodedKeySpec(encodedKey);
                    final KeyFactory keyFactory = KeyFactory.getInstance("DSA");
                    final DSAPublicKey key = (DSAPublicKey) keyFactory.generatePublic(keySpec);
                    y = key.getY();
                    final DSAParams params = key.getParams();
                    p = params.getP();
                    q = params.getQ();
                    g = params.getG();
                    break;
                }
                case OPENSSH_V1: {
                    try {
                        // https://www.rfc-editor.org/rfc/rfc4253#section-6.6
                        final Buffer buffer = new Buffer(encodedKey);
                        buffer.skipString(/* hostKeyAlgorithm */);
                        p = buffer.getBigInteger();
                        q = buffer.getBigInteger();
                        g = buffer.getBigInteger();
                        y = buffer.getBigInteger();
                    } catch (@NonNull final IllegalArgumentException | IOException e) {
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
                    x = buffer.getBigInteger();
                    // y and params are set during public key parsing
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
                    buffer.skipString(/* "ssh-dss" */);

                    p = buffer.getBigInteger();
                    q = buffer.getBigInteger();
                    g = buffer.getBigInteger();

                    y = buffer.getBigInteger();
                    x = buffer.getBigInteger();
                    setPublicKeyComment(buffer.getJString());
                    break;
                }

                case SSH_AGENT: {
                    final Buffer buffer = new Buffer(encodedKey);
                    buffer.skipString(/* "ssh-dss" */);
                    p = buffer.getBigInteger();
                    q = buffer.getBigInteger();
                    g = buffer.getBigInteger();
                    y = buffer.getBigInteger();
                    x = buffer.getBigInteger();
                    setPublicKeyComment(buffer.getJString());
                    break;
                }

                case ASN1: {
                    // Sequence                 ==> 'root'
                    //     Integer(0)           ==> version
                    //     Integer(10745...     ==> p
                    //     Integer(12159...     ==> q
                    //     Integer(57877...     ==> g
                    //     Integer(44240...     ==> y
                    //     Integer(12058...     ==> x
                    final ASN1Sequence root;
                    try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                        // There is no BC DSAPrivateKey ?? we must decode manually
                        root = ASN1Sequence.getInstance(stream.readObject());
                    }

                    p = ASN1Integer.getInstance(root.getObjectAt(1)).getPositiveValue();
                    q = ASN1Integer.getInstance(root.getObjectAt(2)).getPositiveValue();
                    g = ASN1Integer.getInstance(root.getObjectAt(3)).getPositiveValue();

                    y = ASN1Integer.getInstance(root.getObjectAt(4)).getPositiveValue();
                    x = ASN1Integer.getInstance(root.getObjectAt(5)).getPositiveValue();
                    break;
                }

                case PKCS8: {
                    // Sequence                                         ==> 'root'
                    //     Integer(0)                                   ==> version
                    //     Sequence                                     ==> 'subSeq'
                    //         ObjectIdentifier(1.2.840.10040.4.1)      ==> 'prvKeyAlgOID'
                    //         Sequence                                 ==> attributes
                    //             Integer(177451...                    ==> p
                    //             Integer(131449...                    ==> q
                    //             Integer(163872...                    ==> g
                    //     DER Octet String[23]                         ==> 'privateKey'
                    //         02150097...
                    final ASN1Sequence root;
                    try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                        root = ASN1Sequence.getInstance(stream.readObject());
                    }
                    //final ASN1Integer version = ASN1Integer.getInstance(root.getObjectAt(0));
                    final ASN1Sequence subSeq = ASN1Sequence.getInstance(root.getObjectAt(1));
                    final ASN1OctetString privateKeyBlob = ASN1OctetString.getInstance(
                            root.getObjectAt(2));

                    final ASN1Sequence attr = ASN1Sequence.getInstance(subSeq.getObjectAt(1));
                    p = ASN1Integer.getInstance(attr.getObjectAt(0)).getPositiveValue();
                    q = ASN1Integer.getInstance(attr.getObjectAt(1)).getPositiveValue();
                    g = ASN1Integer.getInstance(attr.getObjectAt(2)).getPositiveValue();
                    x = new BigInteger(1, privateKeyBlob.getOctets());
                    //noinspection DataFlowIssue
                    y = g.modPow(x, p);
                    break;
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

        if (p != null) {
            keySize = p.bitLength();
        }

        setPrivateKeyEncrypted(false);
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

        /**
         * Constructor.
         */
        public Builder(@NonNull final SshClientConfig config) {
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
            return new KeyPairDSA(config, this);
        }
    }
}
