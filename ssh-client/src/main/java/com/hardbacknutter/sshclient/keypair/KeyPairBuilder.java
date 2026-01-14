package com.hardbacknutter.sshclient.keypair;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDF;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface KeyPairBuilder {
    /**
     * Set the private key blob and its encoding format.
     *
     * @param privateKeyBlob The encoded private key
     * @param encoding       The vendor specific format of the private key
     *                       This is independent of the encryption state.
     */
    @NonNull
    KeyPairBuilder setPrivateKey(byte @NonNull [] privateKeyBlob,
                                 @NonNull PrivateKeyEncoding encoding);

    /**
     * Set the public key blob and its encoding format.
     *
     * @param publicKeyBlob The encoded private key
     * @param encoding      The vendor specific format of the private key
     *                      This is independent of the encryption state.
     */
    @NonNull
    KeyPairBuilder setPublicKey(byte @Nullable [] publicKeyBlob,
                                @Nullable PublicKeyEncoding encoding);

    /**
     * Set the optional decryptor to use if the key is encrypted.
     *
     * @param decryptor (optional) The vendor specific decryptor
     */
    @NonNull
    KeyPairBuilder setDecryptor(@Nullable PBKDF decryptor);

    @NonNull
    SshKeyPair build()
            throws GeneralSecurityException, IOException;
}
