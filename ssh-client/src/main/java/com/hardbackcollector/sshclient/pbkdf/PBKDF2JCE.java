/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2013-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package com.hardbackcollector.sshclient.pbkdf;

import androidx.annotation.NonNull;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2898">
 * RFC 2898 PKCS #5: Password-Based Cryptography Specification</a>
 * @see <a href="https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#secretkeyfactory-algorithms">
 * Standard algorithm names</a>
 */
public class PBKDF2JCE
        implements PBKDF2 {

    @NonNull
    private final String algorithm;

    /**
     * @param algorithm standard JDK name (e.g. "PBKDF2WithHmacSHA1")
     */
    public PBKDF2JCE(@NonNull final String algorithm) {
        this.algorithm = algorithm;
    }

    public PBKDF2JCE(@NonNull final ASN1ObjectIdentifier oid) {
        this.algorithm = getPBEAlgorithm(oid);
    }

    @NonNull
    private String getPBEAlgorithm(@NonNull final ASN1ObjectIdentifier oid) {

        //not exhaustive, but should hopefully do for now.
        // PBKDF2With<prf>

        if (PKCSObjectIdentifiers.id_hmacWithSHA512.equals(oid)) {
            return "PBKDF2WithHmacSHA512";

        } else if (PKCSObjectIdentifiers.id_hmacWithSHA384.equals(oid)) {
            return "PBKDF2WithHmacSHA384";

        } else if (PKCSObjectIdentifiers.id_hmacWithSHA256.equals(oid)) {
            return "PBKDF2WithHmacSHA256";

        } else if (PKCSObjectIdentifiers.id_hmacWithSHA224.equals(oid)) {
            return "PBKDF2WithHmacSHA224";

        } else {
            return "PBKDF2WithHmacSHA1";
        }
    }

    @Override
    @NonNull
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
                                    @NonNull final byte[] salt,
                                    final int iterations,
                                    final int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        final char[] pass = new char[passphrase.length];
        for (int i = 0; i < passphrase.length; i++) {
            pass[i] = (char) (passphrase[i] & 0xff);
        }

        final KeySpec keySpec = new PBEKeySpec(pass, salt, iterations, keyLength * 8);

        final SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
        return skf.generateSecret(keySpec)
                .getEncoded();
    }
}
