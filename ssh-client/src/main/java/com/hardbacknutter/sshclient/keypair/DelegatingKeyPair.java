package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.signature.SshSignature;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Objects;

public abstract class DelegatingKeyPair
        extends KeyPairBase {

    private static final String MUST_PARSE_FIRST = "Must call decrypt/parse first";
    /** The wrapped/actual KeyPair. Use a concrete reference as we need access to the internals. */
    @Nullable
    KeyPairBase delegate;
    /** Holds the public key blob before the delegate is created. */
    @Nullable
    byte[] publicKeyBlob;
    /** Holds the public key format before the delegate is created. */
    @Nullable
    PublicKeyEncoding publicKeyBlobFormat;
    /** Holds the public key comment before the delegate is created. */
    @NonNull
    private String publicKeyComment = "";

    DelegatingKeyPair(@NonNull final SshClientConfig config,
                      @NonNull final byte[] privateKeyBlob,
                      @NonNull final PrivateKeyEncoding privateKeyEncoding,
                      final boolean encrypted,
                      @Nullable final PKDecryptor decryptor) {
        super(config, privateKeyBlob, privateKeyEncoding, encrypted, decryptor);
    }

    @NonNull
    @Override
    public String getHostKeyAlgorithm()
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getHostKeyAlgorithm();
    }

    @Override
    public int getKeySize() {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getKeySize();
    }

    @Override
    @NonNull
    public String getFingerPrint()
            throws NoSuchAlgorithmException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getFingerPrint();
    }

    @Override
    @NonNull
    public String getFingerPrint(@NonNull final String algorithm)
            throws NoSuchAlgorithmException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getFingerPrint(algorithm);
    }

    @Override
    @NonNull
    public PublicKey getPublicKey()
            throws InvalidKeySpecException,
                   InvalidParameterSpecException,
                   NoSuchAlgorithmException,
                   NoSuchProviderException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getPublicKey();
    }

    @NonNull
    @Override
    protected PrivateKey getPrivateKey()
            throws InvalidKeySpecException,
                   NoSuchAlgorithmException,
                   NoSuchProviderException,
                   InvalidParameterSpecException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getPrivateKey();
    }

    @NonNull
    @Override
    public byte[] getSignature(@NonNull final byte[] data,
                               @NonNull final String algorithm)
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getSignature(data, algorithm);
    }

    @NonNull
    @Override
    public SshSignature getVerifier()
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getVerifier();
    }

    @NonNull
    @Override
    public byte[] toSshAgentEncodedKeyPair()
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).toSshAgentEncodedKeyPair();
    }

    @Override
    public boolean isEncrypted() {
        if (delegate == null) {
            return super.isEncrypted();
        }
        return delegate.isEncrypted();
    }

    @Override
    public void setPrivateKeyEncrypted(final boolean encrypted) {
        if (delegate == null) {
            super.setPrivateKeyEncrypted(encrypted);
            return;
        }
        delegate.setPrivateKeyEncrypted(encrypted);
    }

    @Override
    @NonNull
    public String getPublicKeyComment() {
        if (delegate == null) {
            return publicKeyComment;
        }
        return delegate.getPublicKeyComment();
    }

    @Override
    public void setPublicKeyComment(@Nullable final String comment) {
        if (delegate == null) {
            publicKeyComment = comment != null ? comment : "";
            return;
        }
        delegate.setPublicKeyComment(comment);
    }

    @NonNull
    @Override
    public byte[] getSshEncodedPublicKey() {
        if (delegate == null) {
            Objects.requireNonNull(publicKeyBlob, "publicKeyBlob");
            return publicKeyBlob;
        }
        return delegate.getSshEncodedPublicKey();
    }

    @Override
    void parsePublicKey(@NonNull final byte[] encodedKey,
                        @NonNull final PublicKeyEncoding encoding)
            throws NoSuchAlgorithmException,
                   NoSuchProviderException,
                   InvalidKeySpecException,
                   InvalidKeyException {
        if (delegate != null) {
            delegate.parsePublicKey(encodedKey, encoding);
        }
        publicKeyBlob = encodedKey;
        publicKeyBlobFormat = encoding;
    }


    @Override
    public boolean decrypt(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {
        if (delegate == null) {
            return super.decrypt(passphrase);
        }
        return delegate.decrypt(passphrase);
    }

    @NonNull
    @Override
    byte[] internalDecrypt(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {
        if (delegate == null) {
            return super.internalDecrypt(passphrase);
        }
        return delegate.internalDecrypt(passphrase);
    }

    @Override
    public void dispose() {
        super.dispose();
        if (delegate != null) {
            delegate.dispose();
        }
    }

    void createDelegate(@NonNull final String hostKeyAlgorithm,
                        @NonNull final byte[] plainKey)
            throws GeneralSecurityException, IOException {
        Objects.requireNonNull(privateKeyEncoding, "privateKeyEncoding");

        final KeyPairBuilder builder;

        switch (hostKeyAlgorithm) {
            case HostKeyAlgorithm.SSH_RSA:
                builder = new KeyPairRSA.Builder(config);
                break;

            case HostKeyAlgorithm.SSH_DSS:
                builder = new KeyPairDSA.Builder(config);
                break;

            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521:
                builder = new KeyPairECDSA.Builder(config, hostKeyAlgorithm);
                break;

            case HostKeyAlgorithm.SSH_ED25519:
            case HostKeyAlgorithm.SSH_ED448:
                builder = new KeyPairEdDSA.Builder(config, hostKeyAlgorithm);
                break;

            default:
                throw new UnsupportedAlgorithmException(hostKeyAlgorithm);
        }

        delegate = (KeyPairBase) builder
                .setPrivateKey(plainKey, privateKeyEncoding)
                .setPublicKey(publicKeyBlob, publicKeyBlobFormat)
                .setDecryptor(decryptor)
                .build();
        delegate.setPublicKeyComment(publicKeyComment);
    }

    void createDelegate(@NonNull final ASN1ObjectIdentifier prvKeyAlgOID,
                        @NonNull final byte[] encodedKey)
            throws GeneralSecurityException, IOException {
        Objects.requireNonNull(privateKeyEncoding, "privateKeyEncoding");

        final KeyPairBuilder builder;

        if (PKCSObjectIdentifiers.rsaEncryption.equals(prvKeyAlgOID)) {
            builder = new KeyPairRSA.Builder(config);
        } else if (X9ObjectIdentifiers.id_dsa.equals(prvKeyAlgOID)) {
            builder = new KeyPairDSA.Builder(config);
        } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(prvKeyAlgOID)) {
            builder = new KeyPairECDSA.Builder(config, getHostKeyAlgorithm());
        } else if (EdECObjectIdentifiers.id_Ed25519.equals(prvKeyAlgOID)
                || EdECObjectIdentifiers.id_Ed448.equals(prvKeyAlgOID)) {
            builder = new KeyPairEdDSA.Builder(config, getHostKeyAlgorithm());
        } else {
            throw new UnsupportedAlgorithmException(String.valueOf(prvKeyAlgOID));
        }

        delegate = (KeyPairBase) builder
                .setPrivateKey(encodedKey, privateKeyEncoding)
                .setPublicKey(publicKeyBlob, publicKeyBlobFormat)
                .setDecryptor(decryptor)
                .build();

        delegate.setPublicKeyComment(publicKeyComment);
        // copy the encryption status!
        delegate.setPrivateKeyEncrypted(privateKeyEncrypted);
    }
}
