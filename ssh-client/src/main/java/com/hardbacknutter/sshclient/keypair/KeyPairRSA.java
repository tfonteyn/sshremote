package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.utils.Buffer;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;

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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * The KeyPair implementation for an RSA key pair.
 *
 * <pre>
 * RSA Private Key file (PKCS#1)
 * -----BEGIN RSA PRIVATE KEY-----
 * BASE64 ENCODED DATA
 * -----END RSA PRIVATE KEY-----
 * </pre>
 * Within the base64 encoded data the following DER structure is present:
 * <pre>
 *      RSAPrivateKey ::= SEQUENCE {
 *          version           Version,
 *          modulus           INTEGER,  -- n
 *          publicExponent    INTEGER,  -- e
 *          privateExponent   INTEGER,  -- d
 *          prime1            INTEGER,  -- p
 *          prime2            INTEGER,  -- q
 *          exponent1         INTEGER,  -- d mod (p-1)
 *          exponent2         INTEGER,  -- d mod (q-1)
 *          coefficient       INTEGER,  -- (inverse of q) mod p
 *          otherPrimeInfos   OtherPrimeInfos OPTIONAL
 *      }
 * </pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2">
 * RFC 8017, appendix A.1.2 RSA Private Key Syntax</a>
 */
public class KeyPairRSA
        extends KeyPairBase {

    private static final String serverHostKeyAlgorithm = HostKeyAlgorithm.SSH_RSA;

    /** prime p */
    @Nullable
    private BigInteger p;
    /** prime q */
    @Nullable
    private BigInteger q;

    /** e: publicExponent */
    @Nullable
    private BigInteger publicExponent;
    /** d: privateExponent: e^-1 mod (p-1)(q-1) */
    @Nullable
    private BigInteger privateExponent;
    /** n: modulus   p multiply q */
    @Nullable
    private BigInteger modulus;

    /** prime exponent p  dmp1 == prv mod (p-1) */
    @Nullable
    private BigInteger primeEP;
    /** prime exponent q  dmq1 == prv mod (q-1) */
    @Nullable
    private BigInteger primeEQ;
    /** coefficient  iqmp == modinv(q, p) == q^-1 mod p */
    @Nullable
    private BigInteger coefficient;

    private int keySize = 1024;

    /**
     * Constructor.
     *
     * @param builder to use
     */
    private KeyPairRSA(@NonNull final SshClientConfig config,
                       @NonNull final Builder builder)
            throws GeneralSecurityException {
        super(config, builder.privateKeyBlob, builder.privateKeyFormat,
              builder.encrypted, builder.decryptor);

        modulus = builder.modulus;
        publicExponent = builder.publicExponent;
        privateExponent = builder.privateExponent;
        coefficient = builder.coefficient;
        p = builder.p;
        q = builder.q;

        parse();
    }

    /**
     * Generate a <strong>new</strong> KeyPair of the given key size.
     *
     * @param keySize the number of bits of the key to be produced.
     */
    public KeyPairRSA(@NonNull final SshClientConfig config,
                      final int keySize)
            throws NoSuchAlgorithmException {
        super(config);

        this.keySize = keySize;

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);

        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        final RSAPrivateCrtKey prvKey = (RSAPrivateCrtKey) keyPair.getPrivate();

        privateExponent = prvKey.getPrivateExponent();
        publicExponent = prvKey.getPublicExponent();

        modulus = prvKey.getModulus();
        coefficient = prvKey.getCrtCoefficient();
        p = prvKey.getPrimeP();
        q = prvKey.getPrimeQ();
        primeEP = prvKey.getPrimeExponentP();
        primeEQ = prvKey.getPrimeExponentQ();
    }

    /**
     * Construct the PublicKey based on the components.
     *
     * @param publicExponent the public exponent.
     * @param modulus        the modulus.
     *
     * @return key
     */
    @NonNull
    public static PublicKey createPublicKey(@NonNull final BigInteger publicExponent,
                                            @NonNull final BigInteger modulus)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        final KeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
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
                                    @Nullable final PublicKeyFormat keyFormat)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (encodedKey != null && keyFormat != null) {
            switch (keyFormat) {
                case X509: {
                    final KeySpec keySpec = new X509EncodedKeySpec(encodedKey);
                    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    final RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(keySpec);

                    modulus = key.getModulus();
                    publicExponent = key.getPublicExponent();
                    break;
                }
                case OPENSSH_V1: {
                    try {
                        // https://www.rfc-editor.org/rfc/rfc4253#section-6.6
                        final Buffer buffer = new Buffer(encodedKey);
                        buffer.skipString();
                        publicExponent = buffer.getBigInteger();
                        modulus = buffer.getBigInteger();
                    } catch (@NonNull final IllegalArgumentException | IOException e) {
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
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        Objects.requireNonNull(publicExponent, "publicExponent");
        Objects.requireNonNull(modulus, "modulus");
        return createPublicKey(publicExponent, modulus);
    }

    @NonNull
    protected PrivateKey getPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        Objects.requireNonNull(privateExponent, "privateExponent");
        Objects.requireNonNull(modulus, "modulus");

        final KeySpec keySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    @NonNull
    @Override
    public byte[] getSshEncodedPublicKey() {
        Objects.requireNonNull(publicExponent, "publicExponent");
        Objects.requireNonNull(modulus, "modulus");
        return wrapPublicKey(serverHostKeyAlgorithm,
                             publicExponent.toByteArray(),
                             modulus.toByteArray());
    }

    @NonNull
    @Override
    public byte[] forSSHAgent()
            throws KeyManagementException {
        if (isPrivateKeyEncrypted()) {
            throw new KeyManagementException("key is encrypted.");
        }
        Objects.requireNonNull(privateExponent, "privateExponent");
        Objects.requireNonNull(publicExponent, "publicExponent");
        Objects.requireNonNull(modulus, "modulus");
        Objects.requireNonNull(p, "p");
        Objects.requireNonNull(q, "q");

        calculateCoefficient();
        Objects.requireNonNull(coefficient, "coefficient");

        return new Buffer()
                .putString(serverHostKeyAlgorithm)
                .putMPInt(modulus)
                .putMPInt(publicExponent)
                .putMPInt(privateExponent)
                .putMPInt(coefficient)
                .putMPInt(p)
                .putMPInt(q)
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
                    privateExponent = buffer.getBigInteger();
                    p = buffer.getBigInteger();
                    q = buffer.getBigInteger();
                    coefficient = buffer.getBigInteger();

                    calculateModulus();
                    calculatePrimeEP();
                    calculatePrimeEQ();
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
                    buffer.skipString(/* "ssh-rsa" */);

                    modulus = buffer.getBigInteger();
                    publicExponent = buffer.getBigInteger();
                    privateExponent = buffer.getBigInteger();
                    coefficient = buffer.getBigInteger();
                    p = buffer.getBigInteger();
                    q = buffer.getBigInteger();

                    calculatePrimeEP();
                    calculatePrimeEQ();
                    break;
                }

                case ASN1: {
                    // There are no JCE KeySpec for this format.
                    final org.bouncycastle.asn1.pkcs.RSAPrivateKey key;
                    try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                        key = org.bouncycastle.asn1.pkcs.RSAPrivateKey
                                .getInstance(stream.readObject());
                    }
                    modulus = key.getModulus();
                    publicExponent = key.getPublicExponent();
                    privateExponent = key.getPrivateExponent();
                    p = key.getPrime1();
                    q = key.getPrime2();
                    primeEP = key.getExponent1();
                    primeEQ = key.getExponent2();
                    coefficient = key.getCoefficient();
                    break;
                }

                case PKCS8: {
                    // Sequence                                         ==> 'root'
                    //     Integer(0)                                   ==> version
                    //     Sequence                                     ==> 'subSeq'
                    //         ObjectIdentifier(1.2.840.113549.1.1.1)   ==> 'prvKeyAlgOID'
                    //         NULL                                     ==> attributes, none for RSA
                    //     DER Octet String[1193]                       ==> 'privateKey'
                    //         308204a50...
                    final ASN1Sequence root;
                    try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                        root = ASN1Sequence.getInstance(stream.readObject());
                    }
                    // final ASN1Integer version = ASN1Integer.getInstance(root.getObjectAt(0));
                    // final ASN1Sequence subSeq = ASN1Sequence.getInstance(root.getObjectAt(1));
                    final ASN1OctetString privateKeyBlob = ASN1OctetString.getInstance(
                            root.getObjectAt(2));

                    // final ASN1ObjectIdentifier prvKeyAlgOID = ASN1ObjectIdentifier.getInstance(
                    //        subSeq.getObjectAt(0));

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

        //noinspection ConstantConditions
        keySize = modulus.bitLength();

        setPrivateKeyEncrypted(false);
    }


    /**
     * prime exponent p = prv mod (p-1)
     */
    private void calculatePrimeEP() {
        if (primeEP == null) {
            //noinspection ConstantConditions
            primeEP = privateExponent.mod(p.subtract(BigInteger.ONE));
        }
    }

    private void calculatePrimeEQ() {
        if (primeEQ == null) {
            //noinspection ConstantConditions
            primeEQ = privateExponent.mod(q.subtract(BigInteger.ONE));
        }
    }

    private void calculateCoefficient() {
        if (coefficient == null) {
            //noinspection ConstantConditions
            coefficient = q.modInverse(p);
        }
    }

    private void calculateModulus() {
        if (modulus == null) {
            //noinspection ConstantConditions
            modulus = p.multiply(q);
        }
    }

    public static class Builder {

        @NonNull
        final SshClientConfig config;
        @Nullable
        BigInteger modulus;
        @Nullable
        BigInteger publicExponent;
        @Nullable
        BigInteger privateExponent;
        @Nullable
        BigInteger coefficient;
        @Nullable
        BigInteger p;
        @Nullable
        BigInteger q;
        private byte[] privateKeyBlob;
        private Vendor privateKeyFormat;
        private boolean encrypted;
        @Nullable
        private PKDecryptor decryptor;

        public Builder(@NonNull final SshClientConfig config) {
            this.config = config;
        }

        @NonNull
        public Builder setModulus(@NonNull final BigInteger modulus) {
            this.modulus = modulus;
            return this;
        }

        @NonNull
        public Builder setPublicExponent(@NonNull final BigInteger publicExponent) {
            this.publicExponent = publicExponent;
            return this;
        }

        @NonNull
        public Builder setPrivateExponent(@NonNull final BigInteger privateExponent) {
            this.privateExponent = privateExponent;
            return this;
        }

        @NonNull
        public Builder setCoefficient(@NonNull final BigInteger coefficient) {
            this.coefficient = coefficient;
            return this;
        }

        @NonNull
        public Builder setPrimeP(@NonNull final BigInteger p) {
            this.p = p;
            return this;
        }

        @NonNull
        public Builder setPrimeQ(@NonNull final BigInteger q) {
            this.q = q;
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
            return new KeyPairRSA(config, this);
        }
    }
}
