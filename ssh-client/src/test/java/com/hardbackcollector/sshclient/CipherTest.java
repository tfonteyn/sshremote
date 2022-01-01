package com.hardbackcollector.sshclient;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.hardbackcollector.sshclient.ciphers.SshCipher;
import com.hardbackcollector.sshclient.utils.ImplementationFactory;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;

class CipherTest {

    private static final Logger LOGGER = new DbgJLogger();
    private static final SshClient SSH_CLIENT = new SshClient(LOGGER);

    private static final String longText =
            "Status of This Memo\n"
                    + "\n"
                    + "   This document specifies an Internet standards track protocol for the\n"
                    + "   Internet community, and requests discussion and suggestions for\n"
                    + "   improvements.  Please refer to the current edition of the \"Internet\n"
                    + "   Official Protocol Standards\" (STD 1) for the standardization state\n"
                    + "   and status of this protocol.  Distribution of this memo is unlimited.\n"
                    + "\n"
                    + "Copyright Notice\n"
                    + "\n"
                    + "   Copyright (C) The Internet Society (2006).\n"
                    + "\n"
                    + "Abstract\n"
                    + "\n"
                    + "   The Secure Shell (SSH) is a protocol for secure remote login and\n"
                    + "   other secure network services over an insecure network.\n"
                    + "\n"
                    + "   This document describes the SSH transport layer protocol, which\n"
                    + "   typically runs on top of TCP/IP.  The protocol can be used as a basis\n"
                    + "   for a number of secure network services.  It provides strong\n"
                    + "   encryption, server authentication, and integrity protection.  It may\n"
                    + "   also provide compression.\n"
                    + "\n"
                    + "   Key exchange method, public key algorithm, symmetric encryption\n"
                    + "   algorithm, message authentication algorithm, and hash algorithm are\n"
                    + "   all negotiated.\n"
                    + "\n"
                    + "   This document also describes the Diffie-Hellman key exchange method\n"
                    + "   and the minimal set of algorithms that are needed to implement the\n"
                    + "   SSH transport layer protocol.\n";


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

        System.arraycopy(longText.getBytes(StandardCharsets.UTF_8),
                0, input, 0, longText.length());

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
