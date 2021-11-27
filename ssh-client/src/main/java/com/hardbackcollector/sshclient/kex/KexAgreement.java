package com.hardbackcollector.sshclient.kex;

import androidx.annotation.NonNull;

import javax.crypto.Cipher;

public final class KexAgreement {

    @NonNull
    private final String kexAlgorithm;
    @NonNull
    private final String hostKeyAlgorithm;
    @NonNull
    private final String cipher_c2s;
    @NonNull
    private final String cipher_s2c;
    @NonNull
    private final String mac_c2s;
    @NonNull
    private final String mac_s2c;
    @NonNull
    private final String compression_c2s;
    @NonNull
    private final String compression_s2c;

    KexAgreement(@NonNull final String kexAlgorithm,
                 @NonNull final String hostKeyAlgorithm,
                 @NonNull final String enc_c2s,
                 @NonNull final String enc_s2c,
                 @NonNull final String mac_c2s,
                 @NonNull final String mac_s2c,
                 @NonNull final String compression_c2s,
                 @NonNull final String compression_s2c,
                 @NonNull final String language_c2s,
                 @NonNull final String language_s2c) {
        this.kexAlgorithm = kexAlgorithm;
        this.hostKeyAlgorithm = hostKeyAlgorithm;
        this.cipher_c2s = enc_c2s;
        this.cipher_s2c = enc_s2c;
        this.mac_c2s = mac_c2s;
        this.mac_s2c = mac_s2c;
        this.compression_c2s = compression_c2s;
        this.compression_s2c = compression_s2c;
    }

    @NonNull
    public String getKeyAlgorithm() {
        return kexAlgorithm;
    }

    @NonNull
    public String getHostKeyAlgorithm() {
        return hostKeyAlgorithm;
    }

    @NonNull
    public String getCipher(final int mode) {
        if (mode == Cipher.ENCRYPT_MODE) {
            return cipher_c2s;
        } else {
            //Cipher.DECRYPT_MODE
            return cipher_s2c;
        }
    }

    @NonNull
    public String getMac(final int mode) {
        if (mode == Cipher.ENCRYPT_MODE) {
            return mac_c2s;
        } else {
            //Cipher.DECRYPT_MODE
            return mac_s2c;
        }
    }

    @NonNull
    public String getCompression(final int mode) {
        if (mode == Cipher.ENCRYPT_MODE) {
            return compression_c2s;
        } else {
            //Cipher.DECRYPT_MODE
            return compression_s2c;
        }
    }

    @Override
    @NonNull
    public String toString() {
        return "KexAgreement{" +
                "kexAlgorithm='" + kexAlgorithm + '\'' +
                ", hostKeyAlgorithm='" + hostKeyAlgorithm + '\'' +
                ", cipher_c2s='" + cipher_c2s + '\'' +
                ", cipher_s2c='" + cipher_s2c + '\'' +
                ", mac_c2s='" + mac_c2s + '\'' +
                ", mac_s2c='" + mac_s2c + '\'' +
                ", compression_c2s='" + compression_c2s + '\'' +
                ", compression_s2c='" + compression_s2c + '\'' +
                '}';
    }
}
