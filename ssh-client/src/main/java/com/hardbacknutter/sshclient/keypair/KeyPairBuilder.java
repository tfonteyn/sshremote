package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface KeyPairBuilder {
    /**
     * Set the private key blob and its encoding format.
     *
     * @param privateKeyBlob The encoded private key
     * @param encoding       The vendor specific format of the private key
     *                       This is independent from the encryption state.
     */
    @NonNull
    KeyPairBuilder setPrivateKey(@NonNull final byte[] privateKeyBlob,
                                 @NonNull final PrivateKeyEncoding encoding);

    /**
     * Set the public key blob and its encoding format.
     *
     * @param publicKeyBlob The encoded private key
     * @param encoding      The vendor specific format of the private key
     *                      This is independent from the encryption state.
     */
    @NonNull
    KeyPairBuilder setPublicKey(@Nullable final byte[] publicKeyBlob,
                                @Nullable final PublicKeyEncoding encoding);

    /**
     * Set the optional decryptor to use if the key is encrypted.
     *
     * @param decryptor (optional) The vendor specific decryptor
     */
    @NonNull
    KeyPairBuilder setDecryptor(@Nullable final PKDecryptor decryptor);

    @NonNull
    SshKeyPair build()
            throws GeneralSecurityException, IOException;
}
