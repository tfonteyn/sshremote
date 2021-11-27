/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2012-2018 ymnk, JCraft,Inc. All rights reserved.

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
package com.hardbackcollector.sshclient.macs;

import androidx.annotation.NonNull;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-6.4">
 * RFC 4253 SSH Transport Layer Protocol, 6.4. Data Integrity</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6668#section-2">
 * RFC 6668, 2. Data Integrity</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2104#section-5">
 * RFC 2104 HMAC, section 5. Truncated output</a>
 */
public class SshMacImpl
        implements SshMac {

    private final String algorithm;

    /**
     * The digest length, aka the hash size.
     * RFC 2104, section 2:
     * <pre>
     *      L the byte-length of hash outputs
     * </pre>
     */
    private final int digestLength;
    private final boolean etm;

    /**
     * Temp buffer for writing the sequence uint32 value.
     * We could just (ab)use the tmpBuffer; this is cleaner.
     */
    private final byte[] tmpSeqBuf = new byte[4];

    private Mac mac;
    /**
     * Temp buffer for use in doFinal. This is the BLOCK size of the actual Mac.
     * RFC 2104, section 2:
     * <pre>
     *    The definition of HMAC requires a cryptographic hash function, which
     *    we denote by H, and a secret key K. We assume H to be a cryptographic
     *    hash function where data is hashed by iterating a basic compression
     *    function on blocks of data. We denote by B the byte-length of such
     *    blocks
     * </pre>
     */
    private byte[] macBuffer;

    public SshMacImpl(@NonNull final String algorithm,
                      final int digestLength,
                      final boolean etm) {

        this.algorithm = algorithm;
        this.digestLength = digestLength;
        this.etm = etm;
    }

    @Override
    public boolean isEtm() {
        return etm;
    }

    @Override
    public int getDigestLength() {
        return digestLength;
    }

    @Override
    public void init(@NonNull final byte[] key)
            throws NoSuchAlgorithmException, InvalidKeyException {

        mac = Mac.getInstance(algorithm);
        macBuffer = new byte[mac.getMacLength()];

        final byte[] _key;
        if (key.length > macBuffer.length) {
            //TODO: RFC 2104 section 2:
            // Applications that use keys longer than B bytes will
            // first hash the key using H and then use the
            // resultant L byte string as the actual key to HMAC.
            // Here we just cut it down to size
            _key = new byte[macBuffer.length];
            System.arraycopy(key, 0, _key, 0, macBuffer.length);

        } else {
            // if the key is to small, it will automatically be padded with zeros
            _key = key;
        }

        final Key keySpec = new SecretKeySpec(_key, algorithm);
        mac.init(keySpec);
    }

    @Override
    public void update(final int seq) {
        tmpSeqBuf[0] = (byte) (seq >>> 24);
        tmpSeqBuf[1] = (byte) (seq >>> 16);
        tmpSeqBuf[2] = (byte) (seq >>> 8);
        tmpSeqBuf[3] = (byte) seq;
        mac.update(tmpSeqBuf, 0, 4);
    }

    @Override
    public void update(@NonNull final byte[] input,
                       final int offset,
                       final int len) {
        mac.update(input, offset, len);
    }

    @Override
    public void doFinal(@NonNull final byte[] output,
                        final int outOffset)
            throws ShortBufferException {
        if (digestLength == macBuffer.length) {
            // hash straight to the output buffer
            mac.doFinal(output, outOffset);
        } else {
            // hash in-place,
            mac.doFinal(macBuffer, 0);
            // cut it down to the desired output-length, copying it to the output buffer
            System.arraycopy(macBuffer, 0, output, outOffset, digestLength);
        }
    }
}
