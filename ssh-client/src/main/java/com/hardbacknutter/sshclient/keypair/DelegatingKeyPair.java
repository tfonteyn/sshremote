package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.signature.SshSignature;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Objects;

public abstract class DelegatingKeyPair
        extends KeyPairBase {

    private static final String MUST_PARSE_FIRST = "Must call decrypt/parse first";

    /** The wrapped/actual KeyPair. */
    @Nullable
    protected KeyPairBase delegate;

    DelegatingKeyPair(@NonNull final SshClientConfig config) {
        super(config);
    }

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
    @Nullable
    public String getFingerPrint()
            throws GeneralSecurityException, IOException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getFingerPrint();
    }

    @Override
    @Nullable
    public String getFingerPrint(@NonNull final String algorithm)
            throws GeneralSecurityException, IOException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getFingerPrint(algorithm);
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
    public SshSignature getVerifier(@NonNull final String algorithm)
            throws GeneralSecurityException, IOException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getVerifier(algorithm);
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
            return super.getPublicKeyComment();
        }
        return delegate.getPublicKeyComment();
    }

    @Override
    public void setPublicKeyComment(@Nullable final String comment) {
        if (delegate == null) {
            super.setPublicKeyComment(comment);
            return;
        }
        delegate.setPublicKeyComment(comment);
    }

    @Nullable
    @Override
    public byte[] getSshPublicKeyBlob()
            throws GeneralSecurityException, IOException {
        if (delegate == null) {
            return super.getSshPublicKeyBlob();
        }
        return delegate.getSshPublicKeyBlob();
    }

    @Override
    public void setSshPublicKeyBlob(@Nullable final byte[] publicKeyBlob)
            throws IOException {
        if (delegate == null) {
            super.setSshPublicKeyBlob(publicKeyBlob);
            return;
        }
        delegate.setSshPublicKeyBlob(publicKeyBlob);
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
