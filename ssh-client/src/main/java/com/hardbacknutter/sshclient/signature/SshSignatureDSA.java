package com.hardbacknutter.sshclient.signature;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.utils.Buffer;

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
            final ASN1Sequence root;
            try (ASN1InputStream stream = new ASN1InputStream(sig)) {
                root = ASN1Sequence.getInstance(stream.readObject());
            }

            r = ASN1Integer.getInstance(root.getObjectAt(0)).getPositiveValue();
            s = ASN1Integer.getInstance(root.getObjectAt(1)).getPositiveValue();

        } catch (final IOException e) {
            throw new SignatureException(e);
        }

        return new Buffer()
                .putMPInt(r)
                .putMPInt(s)
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
