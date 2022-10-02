package com.hardbacknutter.sshclient.ciphers;

/**
 * AEAD mode (such as GCM/CCM): "Authenticated Encryption with Additional Data"
 */
public interface AEADCipher {

    /**
     * Get the authentication tag size in BYTES.
     *
     * @return size
     */
    int getTagSizeInBytes();
}
