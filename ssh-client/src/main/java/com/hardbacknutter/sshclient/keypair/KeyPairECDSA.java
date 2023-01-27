package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.util.Vendor;
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
     * This error should only occur when the pair is used as a delegate
     * (e.g. {@link KeyPairOpenSSHv1} in which case calling the related method
     * is a bug.
     */
    private static final String ERROR_EC_TYPE_WAS_NULL = "ecType was null; using a delegate?";

    @Nullable
    private ECKeyType ecType;

    /** private key value. */
    @Nullable
    private BigInteger s;
    /** The public point W. */
    @Nullable
    private ECPoint w;

    /**
     * Constructor.
     *
     * @param privateKeyBlob to use
     * @param ecType         {@link ECKeyType}
     */
    KeyPairECDSA(@NonNull final SshClientConfig config,
                 @NonNull final PrivateKeyBlob privateKeyBlob,
                 @NonNull final ECKeyType ecType)
            throws GeneralSecurityException {
        super(config, privateKeyBlob);

        this.ecType = ecType;

        parse();
    }

    /**
     * Constructor.
     *
     * @param builder to use
     */
    private KeyPairECDSA(@NonNull final SshClientConfig config,
                         @NonNull final Builder builder)
            throws GeneralSecurityException {
        super(config, builder);

        this.ecType = builder.ecType;
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
        this.ecType = ECKeyType.getByKeySize(keySize);

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        final AlgorithmParameterSpec params = new ECGenParameterSpec(ecType.curveName);
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
        Objects.requireNonNull(ecType, ERROR_EC_TYPE_WAS_NULL);
        return ecType.hostKeyAlgorithm;
    }

    @Override
    public int getKeySize() {
        Objects.requireNonNull(ecType, ERROR_EC_TYPE_WAS_NULL);
        return ecType.keySize;
    }

    @Nullable
    @Override
    public byte[] getSshPublicKeyBlob()
            throws GeneralSecurityException {
        final byte[] keyBlob = super.getSshPublicKeyBlob();
        if (keyBlob != null) {
            return keyBlob;
        }

        if (w == null) {
            return null;
        }

        Objects.requireNonNull(ecType, ERROR_EC_TYPE_WAS_NULL);

        return wrapPublicKey(ecType.hostKeyAlgorithm,
                             ecType.nistName.getBytes(StandardCharsets.UTF_8),
                             ecType.encodePoint(w));
    }

    @NonNull
    public byte[] getSignature(@NonNull final byte[] data,
                               @NonNull final String algorithm)
            throws GeneralSecurityException {

        final SshSignature sig = ImplementationFactory.getSignature(config, algorithm);
        sig.init(algorithm);

        //noinspection ConstantConditions
        sig.initSign(generatePrivate(ecType.curveName, s));
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

        if (w == null && this.getSshPublicKeyBlob() != null) {
            final Buffer buffer = new Buffer(this.getSshPublicKeyBlob());
            buffer.skipString(/* hostKeyAlgorithmName */);
            buffer.skipString(/* nistName */);
            w = ECKeyType.decodePoint(buffer.getString());
        }

        //noinspection ConstantConditions
        sig.initVerify(generatePublic(ecType.curveName, w));
        return sig;
    }

    @NonNull
    @Override
    public byte[] forSSHAgent()
            throws KeyManagementException {
        if (privateKeyBlob.isEncrypted()) {
            throw new KeyManagementException("key is encrypted");
        }
        //noinspection ConstantConditions
        return new Buffer()
                .putString((ecType.hostKeyAlgorithm))
                .putString(ecType.nistName)
                .putString(ecType.encodePoint(w))
                .putBigInteger(s)
                .putString(publicKeyComment)
                .getPayload();
    }

    @Override
    void parse(@NonNull final byte[] encodedKey,
               @NonNull final Vendor keyFormat)
            throws GeneralSecurityException {

        try {
            switch (keyFormat) {
                case PUTTY3:
                case PUTTY2:
                    throw new InvalidKeyException("Parsing PuTTY ECDSA keys is not supported");

                case OPENSSH_V1: {
                    final Buffer buffer = new Buffer(encodedKey);
                    // 64-bit dummy checksum  # a random 32-bit int, repeated
                    final int checkInt1 = buffer.getInt();
                    final int checkInt2 = buffer.getInt();
                    if (checkInt1 != checkInt2) {
                        throw new InvalidKeyException("checksum failed");
                    }
                    ecType = ECKeyType.getByHostKeyAlgorithm(buffer.getJString());
                    buffer.skipString(/* nist name*/);

                    w = ECKeyType.decodePoint(buffer.getString());
                    s = buffer.getBigInteger();
                    publicKeyComment = buffer.getJString();

                    break;
                }

                case PKCS8:
                case PKCS5:
                default: {
                    final ASN1InputStream stream = new ASN1InputStream(encodedKey);
                    final ECPrivateKey key = ECPrivateKey.getInstance(stream.readObject());
                    w = ECKeyType.decodePoint(key.getPublicKey().getBytes());
                    s = key.getKey();

                    this.ecType = ECKeyType.getByECPoint(w);
                    break;
                }
            }
        } catch (final GeneralSecurityException e) {
            throw e;

        } catch (final Exception e) {
            if (config.getLogger().isEnabled(Logger.DEBUG)) {
                config.getLogger().log(Logger.DEBUG, () ->
                        "Parsing failed, key is probably encrypted");
            }

            privateKeyBlob.setEncrypted(true);
            return;
        }

        privateKeyBlob.setEncrypted(false);
    }

    @NonNull
    @Override
    public byte[] getEncoded()
            throws InvalidKeyException, IOException {
        if (ecType == null || s == null) {
            throw new InvalidKeyException("No key data");
        }

        if (w != null) {
            return new ECPrivateKey(ecType.keySize, s,
                                    new DERBitString(ecType.encodePoint(w)), ecType.keyOid)
                    .getEncoded();
        } else {
            return new ECPrivateKey(ecType.keySize, s, null, null)
                    .getEncoded();
        }
    }

    public static class Builder
            extends BaseKeyPairBuilder {

        @Nullable
        private ECKeyType ecType;

        @Nullable
        private ECPoint w;

        @Nullable
        private BigInteger s;

        public Builder(@NonNull final SshClientConfig config) {
            super(config);
        }

        @NonNull
        public Builder setType(@NonNull final ECKeyType ecType) {
            this.ecType = ecType;
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

        @NonNull
        @Override
        public SshKeyPair build()
                throws GeneralSecurityException {
            return new KeyPairECDSA(config, this);
        }
    }
}
