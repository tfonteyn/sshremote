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
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;

import java.io.IOException;
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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
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
        final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();

        privateExponent = prvKey.getPrivateExponent();
        publicExponent = pubKey.getPublicExponent();

        modulus = prvKey.getModulus();
        coefficient = prvKey.getCrtCoefficient();
        p = prvKey.getPrimeP();
        q = prvKey.getPrimeQ();
        primeEP = prvKey.getPrimeExponentP();
        primeEQ = prvKey.getPrimeExponentQ();
    }

    /**
     * Construct the PrivateKey based on the components.
     *
     * @param privateExponent the private exponent.
     * @param modulus         the modulus.
     *
     * @return key
     */
    @SuppressWarnings("WeakerAccess")
    @NonNull
    public static PrivateKey generatePrivate(@NonNull final BigInteger privateExponent,
                                             @NonNull final BigInteger modulus)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        final KeySpec keySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
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
    public static PublicKey generatePublic(@NonNull final BigInteger publicExponent,
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
        if (publicExponent == null || modulus == null) {
            return null;
        }

        return wrapPublicKey(serverHostKeyAlgorithm.getBytes(StandardCharsets.UTF_8),
                             publicExponent.toByteArray(),
                             modulus.toByteArray());
    }

    @Override
    public void setSshPublicKeyBlob(@Nullable final byte[] publicKeyBlob) {
        super.setSshPublicKeyBlob(publicKeyBlob);

//        if (publicKeyBlob != null) {
//            if (privateKeyFormat == Vendor.ASN1) {
//                try {
//                    final Buffer buffer = new Buffer(publicKeyBlob);
//                    buffer.skipString(/* serverHostKeyAlgorithm */);
//                    publicExponent = buffer.getBigInteger();
//                    modulus = buffer.getBigInteger();
//                } catch (@NonNull final IOException e) {
//                    if (config.getLogger().isEnabled(Logger.DEBUG)) {
//                        config.getLogger().log(Logger.DEBUG, e, () -> DEBUG_KEY_PARSING_FAILED);
//                    }
//                }
//            }
//        }
    }

    @NonNull
    @Override
    public byte[] getSignature(@NonNull final byte[] data,
                               @NonNull final String algorithm)
            throws GeneralSecurityException {

        final SshSignature sig = ImplementationFactory.getSignature(config, algorithm);
        sig.init(algorithm);

        //noinspection ConstantConditions
        sig.initSign(generatePrivate(privateExponent, modulus));
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

        final byte[] publicKeyBlob = this.getSshPublicKeyBlob();
        if (publicExponent == null && modulus == null && publicKeyBlob != null) {
            final Buffer buffer = new Buffer(publicKeyBlob);
            buffer.skipString(/* "ssh-rsa" */);
            publicExponent = buffer.getBigInteger();
            modulus = buffer.getBigInteger();
        }

        Objects.requireNonNull(publicExponent);
        Objects.requireNonNull(modulus);
        sig.initVerify(generatePublic(publicExponent, modulus));
        return sig;
    }

    @NonNull
    @Override
    public byte[] forSSHAgent()
            throws KeyManagementException {
        if (isPrivateKeyEncrypted()) {
            throw new KeyManagementException("key is encrypted.");
        }

        calculateCoefficient();

        //noinspection ConstantConditions
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
                case PUTTY3:
                case PUTTY2: {
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
                    final RSAPrivateKey key;
                    try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                        key = RSAPrivateKey.getInstance(stream.readObject());
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

    @NonNull
    @Override
    public byte[] getEncoded()
            throws InvalidKeyException, IOException {
        if (modulus == null) {
            throw new InvalidKeyException("No key data");
        }

        // 0, the version
        final byte[] versionInt = new byte[1];

        final ASN1EncodableVector rs = new ASN1EncodableVector();
        rs.add(new ASN1Integer(versionInt));
        rs.add(new ASN1Integer(modulus));
        //noinspection ConstantConditions
        rs.add(new ASN1Integer(publicExponent));
        //noinspection ConstantConditions
        rs.add(new ASN1Integer(privateExponent));
        //noinspection ConstantConditions
        rs.add(new ASN1Integer(p));
        //noinspection ConstantConditions
        rs.add(new ASN1Integer(q));
        //noinspection ConstantConditions
        rs.add(new ASN1Integer(primeEP));
        //noinspection ConstantConditions
        rs.add(new ASN1Integer(primeEQ));
        //noinspection ConstantConditions
        rs.add(new ASN1Integer(coefficient));
        // version 0, hence no 'otherPrimeInfos' added.

        return new DERSequence(rs).getEncoded();
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
            return new KeyPairRSA(config, this);
        }
    }
}
