package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.utils.Buffer;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

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
import java.util.Objects;

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
        super(config, builder.privateKeyBlob, builder.privateKeyFormat,
              builder.encrypted, builder.decryptor);

        p = builder.p;
        q = builder.q;
        g = builder.g;
        y = builder.y;
        x = builder.x;

        parse();
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
        // JCE provides direct access; no need to use getEncoded() + parse()
        final DSAPrivateKey prvKey = (DSAPrivateKey) keyPairGen.getPrivate();
        final DSAPublicKey pubKey = (DSAPublicKey) keyPairGen.getPublic();

        final DSAParams params = prvKey.getParams();

        this.p = params.getP();
        this.q = params.getQ();
        this.g = params.getG();
        this.y = pubKey.getY();
        this.x = prvKey.getX();
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
    public void setEncodedPublicKey(@Nullable final byte[] encodedKey,
                                    @Nullable final PublicKeyFormat keyFormat) {
        if (encodedKey != null && keyFormat != null) {
            try {
                switch (keyFormat) {
                    case X509: {
                        // Sequence                                             ==> 'root'
                        //    Sequence                                          ==> 'subSeq'
                        //        ObjectIdentifier(1.2.840.10040.4.1)           ==> 'oid'
                        //        Sequence                                      ==> 'params'
                        //            Integer(32297387747201053186540584898...  ==> 'p'
                        //            Integer(71207178785611282044091955018...  ==> 'q'
                        //            Integer(26478369615294946530586257630...  ==> 'g'
                        //    DER Bit String[261, 0]                            ==> 'y'
                        //        0282010100800881da19906c314a98ec47a05671f...
                        final ASN1Sequence root;
                        try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                            root = ASN1Sequence.getInstance(stream.readObject());
                        }
                        if (config.getLogger().isEnabled(Logger.DEBUG)) {
                            config.getLogger().log(Logger.DEBUG, () ->
                                    "~~~ KeyPairDSA#setSshPublicKeyBlob ~~~\n" +
                                            ASN1Dump.dumpAsString(root, true));
                        }

                        final ASN1Sequence subSeq = ASN1Sequence.getInstance(
                                root.getObjectAt(0));
                        final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(
                                subSeq.getObjectAt(0));
                        if (!X9ObjectIdentifiers.id_dsa.equals(oid)) {
                            throw new UnsupportedKeyBlobEncodingException(String.valueOf(oid));
                        }

                        //    DSS-Parms ::= SEQUENCE {
                        //     p  INTEGER,
                        //     q  INTEGER,
                        //     g  INTEGER
                        //   }
                        final ASN1Sequence params = ASN1Sequence.getInstance(subSeq.getObjectAt(1));
                        p = ASN1Integer.getInstance(params.getObjectAt(0)).getPositiveValue();
                        q = ASN1Integer.getInstance(params.getObjectAt(1)).getPositiveValue();
                        g = ASN1Integer.getInstance(params.getObjectAt(2)).getPositiveValue();

                        final ASN1BitString bitString = ASN1BitString.getInstance(
                                root.getObjectAt(1));
                        // DSAPublicKey ::= INTEGER --  public key, y
                        y = ASN1Integer.getInstance(bitString.getBytes()).getPositiveValue();

                        break;
                    }
                    case OPENSSH_V1: {
                        // https://www.rfc-editor.org/rfc/rfc4253#section-6.6
                        final Buffer buffer = new Buffer(encodedKey);
                        buffer.skipString();
                        p = buffer.getBigInteger();
                        q = buffer.getBigInteger();
                        g = buffer.getBigInteger();
                        y = buffer.getBigInteger();
                        break;
                    }
                    default:
                        throw new UnsupportedKeyBlobEncodingException(keyFormat);
                }
            } catch (@NonNull final IllegalArgumentException | IOException e) {
                if (config.getLogger().isEnabled(Logger.DEBUG)) {
                    config.getLogger().log(Logger.DEBUG, e, () ->
                            "~~~ KeyPairDSA#setSshPublicKeyBlob ~ Exception ~~~\n");
                }
            }
        }
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
    public byte[] forSSHAgent()
            throws KeyManagementException {
        if (isPrivateKeyEncrypted()) {
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

    @Override
    void parsePrivateKey(@NonNull final byte[] encodedKey,
                         @NonNull final Vendor keyFormat)
            throws GeneralSecurityException {

        try {
            switch (keyFormat) {
                case PUTTY_V3:
                case PUTTY_V2: {
                    final Buffer buffer = new Buffer(encodedKey);
                    x = buffer.getBigInteger();
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

                    if (config.getLogger().isEnabled(Logger.DEBUG)) {
                        config.getLogger()
                              .log(Logger.DEBUG, () -> "~~~ KeyPairDSA#parsePrivateKey ~~~\n" +
                                      ASN1Dump.dumpAsString(root, true));
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
                    y = g.modPow(x, p);
                    break;
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

        if (p != null) {
            keySize = p.bitLength();
        }

        setPrivateKeyEncrypted(false);
    }

    @NonNull
    @Override
    public byte[] getEncoded()
            throws InvalidKeyException, IOException {

        if (p == null || q == null || g == null || y == null || x == null) {
            throw new InvalidKeyException("No key data");
        }

        // 0, the version
        final byte[] versionInt = new byte[1];

        final ASN1EncodableVector rs = new ASN1EncodableVector();
        rs.add(new ASN1Integer(versionInt));
        rs.add(new ASN1Integer(p));
        rs.add(new ASN1Integer(q));
        rs.add(new ASN1Integer(g));
        rs.add(new ASN1Integer(y));
        rs.add(new ASN1Integer(x));

        return new DERSequence(rs).getEncoded();
    }

    public static class Builder {

        @NonNull
        final SshClientConfig config;
        @Nullable
        private BigInteger x;
        @Nullable
        private BigInteger y;
        @Nullable
        private BigInteger p;
        @Nullable
        private BigInteger q;
        @Nullable
        private BigInteger g;
        private byte[] privateKeyBlob;
        private Vendor privateKeyFormat;
        private boolean encrypted;
        @Nullable
        private PKDecryptor decryptor;

        /**
         * Constructor.
         */
        public Builder(@NonNull final SshClientConfig config) {
            this.config = config;
        }

        @NonNull
        public Builder setPQG(@NonNull final BigInteger p,
                              @NonNull final BigInteger q,
                              @NonNull final BigInteger g) {
            this.p = p;
            this.q = q;
            this.g = g;

            // if we have x, then we can calculate y
            if (y == null && x != null) {
                this.y = this.g.modPow(this.x, this.p);
            }
            return this;
        }

        /**
         * Set the value of the private key
         */
        @NonNull
        public Builder setX(@NonNull final BigInteger x) {
            this.x = x;
            return this;
        }

        /**
         * Set the value of the public key
         */
        @NonNull
        public Builder setY(@NonNull final BigInteger y) {
            this.y = y;
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
            // 'privateKey' is an octet string, we can just set the 'x' value
            // and calculate the 'y' from it.
            this.x = new BigInteger(1, privateKeyBlob);

            // If we have p/q, then we can calculate y
            if (y == null && p != null && g != null) {
                this.y = this.g.modPow(this.x, this.p);
            }
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
            return new KeyPairDSA(config, this);
        }
    }
}
