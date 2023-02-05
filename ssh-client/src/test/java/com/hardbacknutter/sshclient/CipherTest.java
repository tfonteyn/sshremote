package com.hardbacknutter.sshclient;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;

class CipherTest {

    private static final Logger LOGGER = new DbgJLogger();
    private static final SshClient SSH_CLIENT = new SshClient(LOGGER);

    @Test
    void legacy()
            throws GeneralSecurityException {

        final SshClientConfig config = SSH_CLIENT.getConfig();

        runSimpleCipher(config, "twofish-cbc");
        runSimpleCipher(config, "twofish256-cbc");
        runSimpleCipher(config, "twofish192-cbc");
        runSimpleCipher(config, "twofish128-cbc");

        runSimpleCipher(config, "twofish256-ctr");
        runSimpleCipher(config, "twofish192-ctr");
        runSimpleCipher(config, "twofish128-ctr");

        runSimpleCipher(config, "blowfish-cbc");

        runSimpleCipher(config, "cast128-cbc");
        runSimpleCipher(config, "cast128-ctr");

        runSimpleCipher(config, "seed-cbc@ssh.com");

        runSimpleCipher(config, "3des-cbc");
        runSimpleCipher(config, "3des-ctr");
    }

    @Test
    void simpleCiphers()
            throws GeneralSecurityException {

        final SshClientConfig config = SSH_CLIENT.getConfig();

        runSimpleCipher(config, "aes256-ctr");
        runSimpleCipher(config, "aes192-ctr");
        runSimpleCipher(config, "aes128-ctr");

        runSimpleCipher(config, "aes256-cbc");
        runSimpleCipher(config, "aes192-cbc");
        runSimpleCipher(config, "aes128-cbc");

        runSimpleCipher(config, "none");
    }

    private void runSimpleCipher(final SshClientConfig config,
                                 final String cipher)
            throws java.security.GeneralSecurityException {
        runSimpleCipher(ImplementationFactory.getCipher(config, cipher));
    }

    private void runSimpleCipher(final SshCipher cipher)
            throws java.security.GeneralSecurityException {

        final byte[] input = new byte[10000];
        final byte[] encoded = new byte[20000];
        final byte[] decoded = new byte[10000];

        final byte[] bytes = LongText.getBytes();
        System.arraycopy(bytes, 0, input, 0, bytes.length);

        cipher.init(Cipher.ENCRYPT_MODE, new byte[32], new byte[64]);
        cipher.update(input, 0, input.length, encoded, 0);

        cipher.init(Cipher.DECRYPT_MODE, new byte[32], new byte[64]);
        cipher.update(encoded, 0, input.length, decoded, 0);

        assertArrayEquals(input, decoded, cipher.toString());
    }

//    @Test
//    void gcmCiphers()
//        throws Exception {
//        runGcmCipher(new AES128GCM());
//        runGcmCipher(new AES256GCM());
//    }
//
//    private void runGcmCipher(final AESnnnGCM cipher) throws Exception {
//        final byte[] input = new byte[10000];
//        final byte[] encoded = new byte[20000];
//        final byte[] decoded = new byte[10000];
//
//        System.arraycopy(longText.getBytes(StandardCharsets.UTF_8),
//                         0, input, 0, longText.length());
//
//        // Just using a set of empty buffers;
//        // It's to test the 'init/update'; not the cipher itself.
//        cipher.init(Cipher.ENCRYPT_MODE, new byte[32], new byte[64]);
//        cipher.doFinal(input, 0, input.length, encoded, 0);
//
//        cipher.init(Cipher.DECRYPT_MODE, new byte[32], new byte[64]);
//        cipher.doFinal(encoded, 0, input.length, decoded, 0);
//
//        assertArrayEquals(input, decoded, cipher.toString());
//    }

}
