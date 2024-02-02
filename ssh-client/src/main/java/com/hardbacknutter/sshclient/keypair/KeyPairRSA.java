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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDF;
import com.hardbacknutter.sshclient.utils.Buffer;

import org.bouncycastle.asn1.ASN1InputStream;

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
 *         RFC 8017, appendix A.1.2 RSA Private Key Syntax</a>
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
    public byte[] toSshAgentEncodedKeyPair()
            throws KeyManagementException {
        if (isEncrypted()) {
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
                    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    final RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(keySpec);

                    modulus = key.getModulus();
                    publicExponent = key.getPublicExponent();
                    break;
                }
                case OPENSSH_V1: {
                    try {
                        final Buffer buffer = new Buffer(encodedKey);
                        buffer.skipString(/* hostKeyAlgorithm */);
                        publicExponent = buffer.getBigInteger();
                        modulus = buffer.getBigInteger();
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
                    privateExponent = buffer.getBigInteger();
                    p = buffer.getBigInteger();
                    q = buffer.getBigInteger();
                    coefficient = buffer.getBigInteger();

                    calculateModulus();
                    calculatePrimeEP();
                    calculatePrimeEQ();
                    // publicExponent is set during public key parsing
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
                    setPublicKeyComment(buffer.getJString());

                    calculatePrimeEP();
                    calculatePrimeEQ();
                    break;
                }

                case SSH_AGENT: {
                    final Buffer buffer = new Buffer(encodedKey);
                    buffer.skipString(/* "ssh-rsa" */);
                    modulus = buffer.getBigInteger();
                    publicExponent = buffer.getBigInteger();
                    privateExponent = buffer.getBigInteger();
                    coefficient = buffer.getBigInteger();
                    p = buffer.getBigInteger();
                    q = buffer.getBigInteger();
                    setPublicKeyComment(buffer.getJString());

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
                    final KeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
                    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    final RSAPrivateCrtKey key =
                            (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
                    modulus = key.getModulus();
                    publicExponent = key.getPublicExponent();
                    privateExponent = key.getPrivateExponent();
                    p = key.getPrimeP();
                    q = key.getPrimeQ();
                    primeEP = key.getPrimeExponentP();
                    primeEQ = key.getPrimeExponentQ();
                    coefficient = key.getCrtCoefficient();
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
        public Builder setDecryptor(@Nullable final PBKDF decryptor) {
            this.decryptor = decryptor;
            this.encrypted = decryptor != null;
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
        public SshKeyPair build()
                throws GeneralSecurityException {
            return new KeyPairRSA(config, this);
        }
    }
}
