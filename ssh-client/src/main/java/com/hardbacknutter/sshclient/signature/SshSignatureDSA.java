package com.hardbacknutter.sshclient.signature;

import androidx.annotation.NonNull;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;

public class SshSignatureDSA
        extends SshSignatureBase {

    // result must be 40 bytes
    private static final int SIG_LEN = 40;
    //length of r and s may not exceed 20 bytes
    private static final int INT_LEN = 20;

    public SshSignatureDSA(@NonNull final String jcaSignatureAlgorithm) {
        super(jcaSignatureAlgorithm);
    }

    private static void putBigInteger(@NonNull final BigInteger value,
                                      final byte[] result,
                                      final int offset) {
        final byte[] data = value.toByteArray();
        final boolean maxExceeded = data.length > INT_LEN;
        final int dstOffset = maxExceeded ? 0 : (INT_LEN - data.length);
        System.arraycopy(data, maxExceeded ? 1 : 0,
                         result, offset + dstOffset,
                         Math.min(INT_LEN, data.length));
    }

    @NonNull
    @Override
    public byte[] sign()
            throws SignatureException {

        // sig is in ASN.1  ::=  SEQUENCE { r INTEGER, s INTEGER  }
        final byte[] sig = signature.sign();

        //   The value for 'signatureBlob' is encoded as a string containing
        //   r, followed by s (which are 160-bit integers, without lengths or
        //   padding, unsigned, and in network byte order).
        try {
            final ASN1Sequence root;
            try (ASN1InputStream stream = new ASN1InputStream(sig)) {
                root = ASN1Sequence.getInstance(stream.readObject());
            }

            final BigInteger r = ASN1Integer.getInstance(root.getObjectAt(0)).getPositiveValue();
            final BigInteger s = ASN1Integer.getInstance(root.getObjectAt(1)).getPositiveValue();

            final byte[] signatureBlob = new byte[SIG_LEN];
            putBigInteger(r, signatureBlob, 0);
            putBigInteger(s, signatureBlob, INT_LEN);
            return wrap(signatureBlob);

        } catch (final IOException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    public boolean verify(@NonNull final byte[] sig)
            throws SignatureException {

        final byte[] signatureBlob = unwrap(sig);

        // After unwrapping, the blob is 2 raw integers of 20 bytes each.
        // We have to split them into the 2 integers r and s
        final byte[] r = new byte[INT_LEN];
        final byte[] s = new byte[INT_LEN];
        System.arraycopy(signatureBlob, 0, r, 0, INT_LEN);
        System.arraycopy(signatureBlob, INT_LEN, s, 0, INT_LEN);

        // The r and s values must be converted to
        // ASN.1  ::=  SEQUENCE { r INTEGER, s INTEGER  }
        final ASN1EncodableVector rs = new ASN1EncodableVector();
        rs.add(new ASN1Integer(r));
        rs.add(new ASN1Integer(s));
        try {
            return signature.verify((new DERSequence(rs)).getEncoded());
        } catch (final IOException e) {
            throw new SignatureException(e);
        }
    }
}
