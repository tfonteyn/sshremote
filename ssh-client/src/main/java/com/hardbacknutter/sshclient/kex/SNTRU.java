package com.hardbacknutter.sshclient.kex;

public interface SNTRU {

    void init();

    int getPublicKeyLength();

    byte[] getPublicKey();

    int getEncapsulationLength();

    byte[] extractSecret(byte[] encapsulation);
}
