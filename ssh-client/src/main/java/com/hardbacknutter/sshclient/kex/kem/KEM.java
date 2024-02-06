package com.hardbacknutter.sshclient.kex.kem;

import androidx.annotation.NonNull;

/**
 * Key Encapsulation Mechanism.
 */
public interface KEM {

    void init();

    int getPublicKeyLength();

    byte[] getPublicKey();

    int getEncapsulationLength();

    @NonNull
    byte[] extractSecret(byte[] encapsulation);
}
