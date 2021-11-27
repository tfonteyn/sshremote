/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2015-2018 ymnk, JCraft,Inc. All rights reserved.

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
package com.hardbackcollector.sshclient.signature;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.utils.Buffer;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;

/**
 * Base class for plain DSA and ECDSA algorithms.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2">
 * RFC 5656 Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer,
 * section 3: SSH ECC Public Key Algorithm</a>
 * @see <a href="https://www.secg.org/sec2-v2.pdf">sec2-v2.pdf</a>
 */
public class SshSignatureDSA
        extends SshSignatureBase {

    public SshSignatureDSA(@NonNull final String jcaSignatureAlgorithm) {
        super(jcaSignatureAlgorithm);
    }

    @NonNull
    @Override
    public byte[] sign()
            throws SignatureException {

        final byte[] sig = signature.sign();

        final BigInteger r;
        final BigInteger s;

        try {
            // sig is in ASN.1  ::=  SEQUENCE { r INTEGER, s INTEGER  }
            final ASN1InputStream stream = new ASN1InputStream(sig);
            final ASN1Sequence root = ASN1Sequence.getInstance(stream.readObject());

            r = ASN1Integer.getInstance(root.getObjectAt(0)).getPositiveValue();
            s = ASN1Integer.getInstance(root.getObjectAt(1)).getPositiveValue();

        } catch (final IOException e) {
            throw new SignatureException(e);
        }

        return new Buffer()
                .putMPInt(r.toByteArray())
                .putMPInt(s.toByteArray())
                .getPayload();
    }

    @Override
    public boolean verify(@NonNull final byte[] sig)
            throws SignatureException {

        final byte[] signatureBlob = unwrap(sig);

        final Buffer buffer = new Buffer(signatureBlob);
        try {
            final ASN1Encodable r = new ASN1Integer(buffer.getMPInt());
            final ASN1Encodable s = new ASN1Integer(buffer.getMPInt());

            final ASN1EncodableVector rs = new ASN1EncodableVector();
            rs.add(r);
            rs.add(s);
            return signature.verify(new DERSequence(rs).getEncoded());

        } catch (final IOException e) {
            throw new SignatureException(e);
        }
    }
}
