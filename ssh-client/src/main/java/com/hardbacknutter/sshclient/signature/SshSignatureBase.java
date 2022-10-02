package com.hardbacknutter.sshclient.signature;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.utils.Buffer;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

abstract class SshSignatureBase
        implements SshSignature {

    @NonNull
    private final String jcaSignatureAlgorithm;

    Signature signature;

    private String hostKeyAlgorithm;

    /**
     * Constructor.
     *
     * @param jcaSignatureAlgorithm standard JDK digest algorithm name
     */
    SshSignatureBase(@NonNull final String jcaSignatureAlgorithm) {
        this.jcaSignatureAlgorithm = jcaSignatureAlgorithm;
    }

    @Override
    public void init(@NonNull final String hostKeyAlgorithm)
            throws NoSuchAlgorithmException {
        this.hostKeyAlgorithm = hostKeyAlgorithm;
        this.signature = Signature.getInstance(jcaSignatureAlgorithm);
    }

    @Override
    public void update(@NonNull final byte[] data)
            throws SignatureException {
        signature.update(data);
    }

    @Override
    public void initSign(@NonNull final PrivateKey key)
            throws InvalidKeyException {
        signature.initSign(key);
    }

    @NonNull
    @Override
    public byte[] sign()
            throws SignatureException {
        return signature.sign();
    }

    @Override
    public void initVerify(@NonNull final PublicKey key)
            throws InvalidKeyException {
        signature.initVerify(key);
    }

    @Override
    public boolean verify(@NonNull final byte[] sig)
            throws SignatureException {

        final byte[] signatureBlob = unwrap(sig);
        return signature.verify(signatureBlob);
    }

    @SuppressWarnings("WeakerAccess")
    @NonNull
    protected byte[] unwrap(@NonNull final byte[] sig) {
        final Buffer buffer = new Buffer(sig);
        try {
            // Unwrap if needed
            if (hostKeyAlgorithm.equals(buffer.getJString())) {
                return buffer.getString();
            }
        } catch (final IOException ignore) {
            // not wrapped
        }

        return sig;
    }
}
