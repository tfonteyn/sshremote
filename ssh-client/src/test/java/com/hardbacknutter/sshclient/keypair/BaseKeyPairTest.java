package com.hardbacknutter.sshclient.keypair;

import static org.junit.jupiter.api.Assertions.assertTrue;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.DbgJLogger;
import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.keypair.util.KeyPairTool;
import com.hardbacknutter.sshclient.signature.SshSignature;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

class BaseKeyPairTest {

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

    void keyPairTest(@NonNull final String keyType,
                     final int keySize)
            throws GeneralSecurityException, IOException {
        final byte[] text = longText.getBytes(StandardCharsets.UTF_8);

        final KeyPairTool keyPairGen = new KeyPairTool(SSH_CLIENT.getConfig());
        final SshKeyPair keyPair = keyPairGen.generateKeyPair(keyType, keySize);

        final String hostKeyAlgorithm = keyPair.getHostKeyAlgorithm();
        final byte[] sig = keyPair.getSignature(text, hostKeyAlgorithm);

        final SshSignature verifier = keyPair.getVerifier();
        verifier.update(text);

        assertTrue(verifier.verify(sig));
    }

    void keyPairTest(@NonNull final String keyType)
            throws GeneralSecurityException, IOException {
        final byte[] text = longText.getBytes(StandardCharsets.UTF_8);

        final KeyPairTool keyPairGen = new KeyPairTool(SSH_CLIENT.getConfig());
        final SshKeyPair keyPair = keyPairGen.generateKeyPair(keyType);

        final String hostKeyAlgorithm = keyPair.getHostKeyAlgorithm();
        final byte[] sig = keyPair.getSignature(text, hostKeyAlgorithm);

        final SshSignature verifier = keyPair.getVerifier();
        verifier.update(text);

        assertTrue(verifier.verify(sig));
    }
}
