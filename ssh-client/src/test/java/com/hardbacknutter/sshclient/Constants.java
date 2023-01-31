package com.hardbacknutter.sshclient;

import java.nio.charset.StandardCharsets;

public final class Constants {
    public static final String PASSWORD = "secret";
    // Just a random long-ish test.
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
    public static final String RESOURCES = "src/test/resources/";
    public static final String SSH_DSS = "ssh-dss";
    public static final String SSH_RSA = "ssh-rsa";
    public static final String ECDSA_SHA_2_NISTP_256 = "ecdsa-sha2-nistp256";
    public static final String ECDSA_SHA_2_NISTP_384 = "ecdsa-sha2-nistp384";
    public static final String ECDSA_SHA_2_NISTP_521 = "ecdsa-sha2-nistp521";
    public static final String SSH_ED_25519 = "ssh-ed25519";
    public static final String SSH_ED_448 = "ssh-ed448";
    public static final String RSA_SHA_2_512 = "rsa-sha2-512";
    public static final String RSA_SHA_2_256 = "rsa-sha2-256";

    private Constants() {
    }

    public static byte[] getTextBytes() {
        return longText.getBytes(StandardCharsets.UTF_8);
    }
}
