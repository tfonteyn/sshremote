package com.hardbacknutter.sshclient.ciphers;

public final class SshCipherConstants {

    public static final String AES_256_CBC = "aes256-cbc";
    public static final String AES_192_CBC = "aes192-cbc";
    public static final String AES_128_CBC = "aes128-cbc";

    public static final String AES_256_CTR = "aes256-ctr";
    public static final String AES_192_CTR = "aes192-ctr";
    public static final String AES_128_CTR = "aes128-ctr";

    public static final String TRIPLE_DES_CBC = "3des-cbc";
    public static final String TRIPLE_DES_CTR = "3des-ctr";

    public static final String SEED_CBC_SSH_COM = "seed-cbc@ssh.com";

    public static final String CAST_128_CBC = "cast128-cbc";
    public static final String CAST_128_CTR = "cast128-ctr";

    public static final String BLOWFISH_CBC = "blowfish-cbc";
    public static final String BLOWFISH_CTR = "blowfish-ctr";

    public static final String TWOFISH_CBC = "twofish-cbc";
    public static final String TWOFISH_256_CBC = "twofish256-cbc";
    public static final String TWOFISH_192_CBC = "twofish192-cbc";
    public static final String TWOFISH_128_CBC = "twofish128-cbc";

    public static final String TWOFISH_256_CTR = "twofish256-ctr";
    public static final String TWOFISH_192_CTR = "twofish192-ctr";
    public static final String TWOFISH_128_CTR = "twofish128-ctr";

    public static final String AR_C_FOUR = "arcfour";
    public static final String AR_C_FOUR_128 = "arcfour128";
    public static final String AR_C_FOUR_256 = "arcfour256";

    public static final String AES_256_GCM_OPENSSH_COM = "aes256-gcm@openssh.com";
    public static final String AES_128_GCM_OPENSSH_COM = "aes128-gcm@openssh.com";

    public static final String CHACHA20_POLY1305_OPENSSH_COM = "chacha20-poly1305@openssh.com";

    public static final String NONE = "none";

    private SshCipherConstants() {
    }
}
