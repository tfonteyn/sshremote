package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public enum EdKeyType {
    Ed25519(HostKeyAlgorithm.SSH_ED25519,
            EdDSAParameterSpec.Ed25519,
            Ed25519PublicKeyParameters.KEY_SIZE,
            EdECObjectIdentifiers.id_Ed25519
    ),

    Ed448(HostKeyAlgorithm.SSH_ED448,
          EdDSAParameterSpec.Ed448,
          Ed448PublicKeyParameters.KEY_SIZE,
          EdECObjectIdentifiers.id_Ed448
    );

    @NonNull
    public final String hostKeyAlgorithm;
    @NonNull
    public final String curveName;

    public final int keySize;
    @NonNull
    final ASN1ObjectIdentifier keyOid;


    EdKeyType(@NonNull final String hostKeyAlgorithm,
              @NonNull final String curveName,
              final int keySize,
              @NonNull final ASN1ObjectIdentifier keyOid) {

        this.hostKeyAlgorithm = hostKeyAlgorithm;
        this.curveName = curveName;
        this.keySize = keySize;
        this.keyOid = keyOid;
    }

    @NonNull
    public static EdKeyType getByHostKeyAlgorithm(@NonNull final String hostKeyAlgorithm)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.hostKeyAlgorithm.equalsIgnoreCase(hostKeyAlgorithm))
                     .findFirst()
                     .orElseThrow(NoSuchAlgorithmException::new);
    }

    @NonNull
    static EdKeyType getByCurveName(@NonNull final String curveName)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.curveName.equalsIgnoreCase(curveName))
                     .findFirst()
                     .orElseThrow(NoSuchAlgorithmException::new);
    }

    @NonNull
    static EdKeyType getByOid(@NonNull final ASN1ObjectIdentifier oid)
            throws NoSuchAlgorithmException {
        return Arrays.stream(values())
                     .filter(e -> e.keyOid.equals(oid))
                     .findFirst()
                     .orElseThrow(NoSuchAlgorithmException::new);
    }

    // no longer used, but leaving here as "interesting" info.
//    @NonNull
//    byte[] extractPubArray(@NonNull final EdDSAPublicKey pubKey) {
//        final EdECPoint point = new EdECPoint(pubKey.getPointEncoding());
//        final byte[] in = point.getY().toByteArray();
//        // rotate
//        final int len = in.length;
//        final byte[] out = new byte[len];
//        for (int i = 0; i < len; i++) {
//            out[i] = in[len - i - 1];
//        }
//        final byte[] blob = Arrays.copyOf(out, keySize);
//        if (point.isXOdd()) {
//            final int pos = blob.length - 1;
//            blob[pos] = (byte) (blob[pos] | 0x80);
//        }
//        return blob;
//    }
}
