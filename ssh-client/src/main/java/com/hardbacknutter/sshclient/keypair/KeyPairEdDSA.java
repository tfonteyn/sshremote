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
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
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

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8032/">
 * RFC 8032 Edwards-Curve Digital Signature Algorithm (EdDSA)</a>
 */
public class KeyPairEdDSA
        extends KeyPairBase {

    @NonNull
    private final EdKeyType edType;

    @Nullable
    private byte[] pub_array;
    @Nullable
    private byte[] prv_array;

    /**
     * Constructor.
     *
     * @param privateKeyBlob to use
     * @param edType         {@link EdKeyType}
     */
    KeyPairEdDSA(@NonNull final SshClientConfig config,
                 @NonNull final PrivateKeyBlob privateKeyBlob,
                 @NonNull final EdKeyType edType)
            throws GeneralSecurityException {
        super(config, privateKeyBlob);
        this.edType = edType;

        parse();
    }

    /**
     * Constructor.
     *
     * @param builder to use
     */
    private KeyPairEdDSA(@NonNull final SshClientConfig config,
                         @NonNull final Builder builder)
            throws GeneralSecurityException {
        super(config, builder);
        this.edType = builder.edType;
        this.prv_array = builder.prv_array;
        this.pub_array = builder.pub_array;

        parse();
    }

    /**
     * Generate a <strong>new</strong> KeyPair with the given curve.
     *
     * @param edType {@link EdKeyType}
     */
    public KeyPairEdDSA(@NonNull final SshClientConfig config,
                        @NonNull final EdKeyType edType)
            throws GeneralSecurityException {
        super(config);
        this.edType = edType;

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(edType.curveName, "BC");
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        pub_array = edType.extractPubArray((EdDSAPublicKey) keyPair.getPublic());

        @Nullable final byte[] prvKey = keyPair.getPrivate().getEncoded();
        // sanity check for null
        if (prvKey != null) {
            parse(prvKey, Vendor.PKCS8);
        }
    }

    /**
     * Construct the PrivateKey based on the components.
     *
     * @return key
     */
    @SuppressWarnings("WeakerAccess")
    @NonNull
    public static PrivateKey generatePrivate(@NonNull final EdKeyType edType,
                                             @NonNull final byte[] bytes)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

        final KeySpec keySpec;
        try {
            // create as an ASN1 object, so we can read the keySpec from it.
            final PrivateKeyInfo keyInfo = new PrivateKeyInfo(
                    new AlgorithmIdentifier(edType.keyOid),
                    new DEROctetString(bytes));
            keySpec = new PKCS8EncodedKeySpec(keyInfo.getEncoded());

        } catch (final IOException e) {
            throw new InvalidKeySpecException(e);
        }

        final KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", "BC");
        return keyFactory.generatePrivate(keySpec);
    }

    // SunEC, needs Java 15
    // public static PublicKey generatePublic(@NonNull final EdKeyType edType,
    //                                           @NonNull final byte[] bytes)
    //         throws InvalidKeySpecException, NoSuchAlgorithmException,
    //                NoSuchProviderException {
    //
    //     final NamedParameterSpec params = new NamedParameterSpec(edType.curveName);
    //     final EdECPoint edECPoint = new EdECPoint(bytes);
    //     final KeySpec keySpec = new XECPublicKeySpec(params, edECPoint.getY());
    //
    //     final KeyFactory keyFactory = KeyFactory.getInstance(edType.curveName, "SunEC");
    //     return keyFactory.generatePublic(keySpec);
    // }

    /**
     * Construct the PublicKey based on the components.
     *
     * @return key
     */
    @NonNull
    public static PublicKey generatePublic(@NonNull final EdKeyType edType,
                                           @NonNull final byte[] bytes)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

        // create as an ASN1 object, so we can read the keySpec from it.
        final SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(edType.keyOid), bytes);
        final KeySpec keySpec;
        try {
            keySpec = new X509EncodedKeySpec(keyInfo.getEncoded());

        } catch (final IOException e) {
            throw new InvalidKeySpecException(e);
        }
        final KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", "BC");
        return keyFactory.generatePublic(keySpec);
    }

    @NonNull
    @Override
    public String getHostKeyAlgorithm() {
        return edType.hostKeyAlgorithm;
    }

    /**
     * EdDSA uses the length (32 or 57) of the key.
     *
     * @return key size in bytes
     */
    @Override
    public int getKeySize() {
        return edType.keySize;
    }

    @Nullable
    @Override
    public byte[] getSshPublicKeyBlob()
            throws GeneralSecurityException {
        final byte[] keyBlob = super.getSshPublicKeyBlob();
        if (keyBlob != null) {
            return keyBlob;
        }

        if (pub_array == null) {
            return null;
        }
        return wrapPublicKey(edType.hostKeyAlgorithm, pub_array);
    }

    @Override
    @NonNull
    public byte[] getSignature(@NonNull final byte[] data,
                               @NonNull final String algorithm)
            throws GeneralSecurityException {

        final SshSignature sig = ImplementationFactory.getSignature(config, algorithm);
        sig.init(algorithm);

        //noinspection ConstantConditions
        sig.initSign(generatePrivate(edType, prv_array));
        sig.update(data);
        final byte[] signature_blob = sig.sign();
        return wrapSignature(algorithm, signature_blob);
    }

    @Override
    @NonNull
    public SshSignature getVerifier(@NonNull final String algorithm)
            throws GeneralSecurityException, IOException {

        final SshSignature sig = ImplementationFactory.getSignature(config, algorithm);
        sig.init(algorithm);

        if (pub_array == null && this.getSshPublicKeyBlob() != null) {
            final Buffer buffer = new Buffer(this.getSshPublicKeyBlob());
            buffer.skipString();
            pub_array = buffer.getString();
        }

        sig.initVerify(generatePublic(edType, pub_array));
        return sig;
    }

    @Override
    @NonNull
    public byte[] forSSHAgent()
            throws KeyManagementException {

        if (privateKeyBlob.isEncrypted()) {
            throw new KeyManagementException("Key is encrypted");
        }
        if (prv_array == null || pub_array == null) {
            throw new KeyManagementException("pub/prv arrays are not set");
        }

        // concat the private key + the public key
        final byte[] encodedKeys = new byte[prv_array.length + pub_array.length];
        System.arraycopy(prv_array, 0, encodedKeys, 0, prv_array.length);
        System.arraycopy(pub_array, 0, encodedKeys, prv_array.length, pub_array.length);

        return new Buffer()
                .putString(edType.hostKeyAlgorithm)
                .putString(pub_array)
                .putString(encodedKeys)
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
                    throw new InvalidKeyException("Parsing PuTTY EdDSA keys is not supported");

                case OPENSSH_V1: {
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
                    prv_array = Arrays.copyOf(tmp, edType.keySize);

                    publicKeyComment = buffer.getJString();

                    break;
                }

                case PKCS8:
                case PKCS5:
                default: {
                    // Ed25519
                    // Sequence
                    //     Integer(1)
                    //     Sequence
                    //         ObjectIdentifier(1.3.101.112)
                    //     DER Octet String[34]
                    //         0420031...
                    //     Tagged [1] IMPLICIT
                    //         DER Octet String[33]
                    //             0031ae3...

                    // Ed448
                    // Sequence
                    //     Integer(1)
                    //     Sequence
                    //         ObjectIdentifier(1.3.101.113)
                    //     DER Octet String[59]
                    //         0439580...
                    //     Tagged [1] IMPLICIT
                    //         DER Octet String[58]
                    //             00123


                    //TODO: This is silly... we're parsing the input twice
                    final ASN1InputStream stream = new ASN1InputStream(encodedKey);
                    final ASN1Primitive root = stream.readObject();

                    if (config.getLogger().isEnabled(Logger.DEBUG)) {
                        config.getLogger().log(Logger.DEBUG, () -> "~~~ KeyPairEdDSA#parse ~~~\n" +
                                ASN1Dump.dumpAsString(root, true));
                    }

                    final KeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
                    final KeyFactory kf = KeyFactory.getInstance("EdDSA", "BC");
                    final EdDSAPrivateKey prvKey = (EdDSAPrivateKey) kf.generatePrivate(keySpec);
                    // How do we get the byte array from prvKey ??

                    pub_array = edType.extractPubArray(prvKey.getPublicKey());

                    final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(root);
                    final byte[] privateKey = privateKeyInfo.getPrivateKey().getOctets();

                    // TODO: is this really the correct/best way to do this ??
                    // remove the tag + length byte
                    // JDK 15 version of the Ed private key provides a getBytes() method.
                    prv_array = new byte[edType.keySize];
                    System.arraycopy(privateKey, 2, prv_array, 0, edType.keySize);
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

    @Override
    public void dispose() {
        super.dispose();
        if (prv_array != null) {
            Arrays.fill(prv_array, (byte) 0);
        }
    }

    public static class Builder
            extends BaseKeyPairBuilder {

        @NonNull
        private final EdKeyType edType;
        @Nullable
        private byte[] prv_array;
        @Nullable
        private byte[] pub_array;

        public Builder(@NonNull final SshClientConfig config,
                       @NonNull final String hostKeyAlgorithm)
                throws NoSuchAlgorithmException {
            super(config);
            edType = EdKeyType.getByHostKeyAlgorithm(hostKeyAlgorithm);
        }

        @NonNull
        public Builder setPrvArray(@NonNull final byte[] prv_array) {
            this.prv_array = prv_array;
            return this;
        }

        @NonNull
        public Builder setPubArray(@NonNull final byte[] pub_array) {
            this.pub_array = pub_array;
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
