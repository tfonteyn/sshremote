package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.util.Arrays;

class PrivateKeyBlob {

    @SuppressWarnings("FieldNotUsedInToString")
    @Nullable
    private byte[] blob;

    /** The format of the key blob */
    @Nullable
    private Vendor format;

    /** Whether the key is encrypted with a passphrase or not. */
    private boolean encrypted;

    /** key is encrypted - the class that can decrypt it */
    @Nullable
    private PKDecryptor decryptor;

    PrivateKeyBlob() {
    }

    /**
     * Constructor.
     *
     * @param blob      The byte[] with the private key
     * @param format    The vendor specific format of the private key
     *                  This is independent from the encryption state.
     * @param decryptor (optional) The vendor specific decryptor
     *                  When not set, the blob is considered unencrypted.
     */
    PrivateKeyBlob(@NonNull final byte[] blob,
                   @NonNull final Vendor format,
                   @Nullable final PKDecryptor decryptor) {
        this.blob = blob;
        this.format = format;
        this.decryptor = decryptor;
        this.encrypted = decryptor != null;
    }

    /**
     * Get the key blob in the current format (encrypted or not)
     *
     * @return key blob
     */
    @Nullable
    public byte[] getBlob() {
        return blob;
    }

    public void setBlob(@Nullable final byte[] blob) {
        this.blob = blob;
    }

    @Nullable
    public Vendor getFormat() {
        return format;
    }

    public void setFormat(@Nullable final Vendor format) {
        this.format = format;
    }

    void setPKDecryptor(@Nullable final PKDecryptor decryptor) {
        this.decryptor = decryptor;
    }

    @Nullable
    PKDecryptor getDecryptor() {
        return decryptor;
    }

    public boolean isEncrypted() {
        return encrypted;
    }

    public void setEncrypted(final boolean encrypted) {
        this.encrypted = encrypted;
    }

    /**
     * If the blob was not encrypted, we return the blob directly.
     * <p>
     * If it was encrypted, we return the decrypted blob.
     * IMPORTANT: the returned byte[] CAN BE GARBAGE if the data/parameters were incorrect.
     * <p>
     * The returned value MUST be parsed for validity.
     */
    @NonNull
    public byte[] decrypt(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {
        if (blob == null) {
            throw new InvalidKeyException("No key data");
        }

        if (!encrypted) {
            return blob;
        }

        if (passphrase == null) {
            throw new KeyException("Passphrase not set");
        }

        if (decryptor == null) {
            throw new KeyException("PKDecryptor not set");
        }

        final byte[] plainKey = decryptor.decrypt(passphrase, blob);
        // be optimistic, assume all went well. If not, a subsequent parse() will reset this flag
        encrypted = false;
        return plainKey;
    }

    public void dispose() {
        if (blob != null) {
            Arrays.fill(blob, (byte) 0);
        }
    }

    @Override
    @NonNull
    public String toString() {
        return "PrivateKeyBlob{" +
                "encrypted=" + encrypted +
                ", format=" + format +
                ", decryptor=" + decryptor +
                '}';
    }
}
