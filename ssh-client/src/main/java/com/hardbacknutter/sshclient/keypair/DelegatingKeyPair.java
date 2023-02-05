package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.signature.SshSignature;

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

    /** Holds the public key blob before the delegate is created. */
    @Nullable
    protected byte[] publicKeyBlob;
    /** The wrapped/actual KeyPair. */
    @Nullable
    KeyPairBase delegate;
    /** Holds the public key format before the delegate is created. */
    @Nullable
    PublicKeyFormat publicKeyBlobFormat;
    /** Holds the public key comment before the delegate is created. */
    @NonNull
    String publicKeyComment = "";

    DelegatingKeyPair(@NonNull final SshClientConfig config,
                      @NonNull final byte[] privateKeyBlob,
                      @NonNull final Vendor format,
                      final boolean encrypted,
                      @Nullable final PKDecryptor decryptor) {
        super(config, privateKeyBlob, format, encrypted, decryptor);
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
    public byte[] forSSHAgent()
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).forSSHAgent();
    }

    @Override
    public boolean isPrivateKeyEncrypted() {
        if (delegate == null) {
            return super.isPrivateKeyEncrypted();
        }
        return delegate.isPrivateKeyEncrypted();
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
    public void setEncodedPublicKey(@Nullable final byte[] encodedKey,
                                    @Nullable final PublicKeyFormat keyFormat)
            throws InvalidKeyException,
                   InvalidKeySpecException,
                   NoSuchAlgorithmException,
                   NoSuchProviderException {
        if (delegate == null) {
            this.publicKeyBlob = encodedKey;
            this.publicKeyBlobFormat = keyFormat;
            return;
        }
        delegate.setEncodedPublicKey(encodedKey, keyFormat);
    }

    @Override
    public boolean decryptPrivateKey(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {
        if (delegate == null) {
            return super.decryptPrivateKey(passphrase);
        }
        return delegate.decryptPrivateKey(passphrase);
    }

    @NonNull
    @Override
    public byte[] decrypt(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {
        if (delegate == null) {
            return super.decrypt(passphrase);
        }
        return delegate.decrypt(passphrase);
    }

    @Override
    public void dispose() {
        super.dispose();
        if (delegate != null) {
            delegate.dispose();
        }
    }
}
