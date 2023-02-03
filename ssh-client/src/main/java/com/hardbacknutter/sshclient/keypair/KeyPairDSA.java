package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.signature.SshSignature;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.util.ASN1Dump;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
     *
     * @param keySize the number of bits of the key to be produced.
     */
    public KeyPairDSA(@NonNull final SshClientConfig config,
                      final int keySize)
            throws NoSuchAlgorithmException {
        super(config);

        this.keySize = keySize;

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(keySize);
        final KeyPair keyPairGen = keyPairGenerator.generateKeyPair();

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
     * Construct the PrivateKey based on the components.
     *
     * @return key
     */

    @SuppressWarnings("WeakerAccess")
    @NonNull
    public static PrivateKey generatePrivate(@NonNull final BigInteger x,
                                             @NonNull final BigInteger p,
                                             @NonNull final BigInteger q,
                                             @NonNull final BigInteger g)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        final KeySpec keySpec = new DSAPrivateKeySpec(x, p, q, g);
        final KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Construct the PublicKey based on the components.
     *
     * @return key
     */
    @NonNull
    public static PublicKey generatePublic(@NonNull final BigInteger y,
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
        if (p == null || q == null || g == null || y == null) {
            return null;
        }

        return wrapPublicKey(serverHostKeyAlgorithm.getBytes(StandardCharsets.UTF_8),
                             p.toByteArray(),
                             q.toByteArray(),
                             g.toByteArray(),
                             y.toByteArray());
    }

    @Override
    public void setSshPublicKeyBlob(@Nullable final byte[] publicKeyBlob) {
        super.setSshPublicKeyBlob(publicKeyBlob);

//        if (publicKeyBlob != null) {
//            if (privateKeyFormat == Vendor.ASN1) {
//                try {
//                    final Buffer buffer = new Buffer(publicKeyBlob);
//                    buffer.skipString(/* serverHostKeyAlgorithm */);
//                    p = buffer.getBigInteger();
//                    q = buffer.getBigInteger();
//                    g = buffer.getBigInteger();
//                    y = buffer.getBigInteger();
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
        sig.initSign(generatePrivate(x, p, q, g));
        sig.update(data);
        final byte[] signature_blob = sig.sign();
        return wrapSignature(algorithm, signature_blob);
    }

    @NonNull
    @Override
    public SshSignature getVerifier(@NonNull final String algorithm)
            throws GeneralSecurityException, IOException {

        final SshSignature sig = ImplementationFactory.getSignature(config, algorithm);
        sig.init(algorithm);

        final byte[] publicKeyBlob = getSshPublicKeyBlob();
        if (y == null && p == null && publicKeyBlob != null) {
            final Buffer buffer = new Buffer(publicKeyBlob);
            buffer.skipString(/* "ssh-dss" */);
            p = buffer.getBigInteger();
            q = buffer.getBigInteger();
            g = buffer.getBigInteger();
            y = buffer.getBigInteger();
        }
        Objects.requireNonNull(y);
        Objects.requireNonNull(p);
        Objects.requireNonNull(q);
        Objects.requireNonNull(g);
        sig.initVerify(generatePublic(y, p, q, g));
        return sig;
    }

    @NonNull
    @Override
    public byte[] forSSHAgent()
            throws KeyManagementException {
        if (isPrivateKeyEncrypted()) {
            throw new KeyManagementException("key is encrypted.");
        }
        //noinspection ConstantConditions
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
                case PUTTY3:
                case PUTTY2: {
                    final Buffer buffer = new Buffer(encodedKey);
                    x = buffer.getBigInteger();
                    break;
                }
                case OPENSSH_V1: {
                    final Buffer buffer = new Buffer(encodedKey);
                    // 64-bit dummy checksum  # a random 32-bit int, repeated
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

                case RAW: {
                    x = new BigInteger(1, encodedKey);
                    Objects.requireNonNull(g, "private key base 'g' not set");
                    y = g.modPow(x, p);
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
