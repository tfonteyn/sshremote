/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.

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
package com.hardbackcollector.sshclient.ciphers;

import androidx.annotation.NonNull;

/**
 * An implementation of the Cipher {@code none}, i.e. unencrypted transport.
 * This is used during key-exchange until the first real Cipher can be used.
 *
 * <blockquote>
 * The "none" algorithm specifies that no encryption is to be done.
 * Note that this method provides no confidentiality protection, and it
 * is NOT RECOMMENDED.  Some functionality (e.g., password
 * authentication) may be disabled for security reasons if this cipher
 * is chosen.
 * </blockquote>
 * <p>
 * The implementation here consists mainly of no-ops.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-6.3">
 * RFC 4253 SSH Transport Layer Protocol, section 6.3. Encryption</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2410">
 * RFC 2410 The NULL Encryption Algorithm and Its Use With IPsec</a>
 */
public class NullCipher
        implements SshCipher {

    /**
     * @return 0
     */
    @Override
    public int getKeySize() {
        return 0;
    }

    /**
     * @return 1
     */
    @Override
    public int getBlockSize() {
        return 1;
    }

    /**
     * @return 0
     */
    @Override
    public int getIVSize() {
        return 0;
    }


    @Override
    public void init(final int opmode,
                     @NonNull final byte[] keyBuf,
                     @NonNull final byte[] iv) {
    }

    @Override
    public void update(@NonNull final byte[] input,
                       final int inputOffset,
                       final int inputLen,
                       @NonNull final byte[] output,
                       final int outputOffset) {
        System.arraycopy(input, inputOffset, output, outputOffset, inputLen);
    }

    @Override
    public void updateAAD(@NonNull final byte[] src,
                          final int offset,
                          final int len) {

    }

    @Override
    public int doFinal(@NonNull final byte[] input,
                       final int inputOffset,
                       final int inputLen,
                       @NonNull final byte[] output,
                       final int outputOffset) {
        return 0;
    }

    @Override
    public boolean isMode(@NonNull final String mode) {
        return false;
    }

    @NonNull
    @Override
    public String getAlgorithm() {
        return "";
    }

    @NonNull
    @Override
    public String getMode() {
        return "";
    }
}
