package com.hardbackcollector.sshclient.parsing;

import static org.junit.jupiter.api.Assertions.assertTrue;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.DbgJLogger;
import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.keypair.SshKeyPair;
import com.hardbackcollector.sshclient.keypair.util.KeyPairTool;
import com.hardbackcollector.sshclient.keypair.util.KeyPairWriter;
import com.hardbackcollector.sshclient.signature.SshSignature;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

abstract class BaseLoadTest {

    static final String TEST_RESOURCES = "src/test/resources/";

    static final SshClient SSH_CLIENT = new SshClient();
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

    static {
        SshClient.setLogger(new DbgJLogger());
    }

    SshKeyPair parseFile(@NonNull final String pathname,
                         @Nullable final String passPhrase)
            throws IOException, GeneralSecurityException {
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n" +
                "parseFile: " + pathname);

        final File prv = new File(pathname);

        final KeyPairTool keyPairTool = new KeyPairTool(SSH_CLIENT.getConfig());
        final SshKeyPair keyPair = keyPairTool.load(prv.getAbsolutePath());
        final byte[] pp = passPhrase != null ? passPhrase.getBytes(StandardCharsets.UTF_8) : null;

        assertTrue(keyPair.decryptPrivateKey(pp), "Failed to decrypt");
        return keyPair;
    }

    void signAndVerify(@NonNull final SshKeyPair keyPair)
            throws GeneralSecurityException, IOException {
        final byte[] text = longText.getBytes(StandardCharsets.UTF_8);

        final String hostKeyAlgorithm = keyPair.getHostKeyAlgorithm();
        final byte[] sig = keyPair.getSignature(text, hostKeyAlgorithm);
        final SshSignature verifier = keyPair.getVerifier();
        verifier.update(text);
        assertTrue(verifier.verify(sig));
    }

    void write(@NonNull final SshKeyPair keyPair,
               @Nullable final String passPhrase)
            throws GeneralSecurityException {
        final KeyPairWriter keyPairWriter = new KeyPairWriter();

        try (final PrintWriter out = new PrintWriter(System.out, true, StandardCharsets.UTF_8)) {
            keyPairWriter.writePublicKey(keyPair, out, keyPair.getPublicKeyComment());
        }
    }
}
