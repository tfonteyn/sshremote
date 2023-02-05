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
        return wrap(signature.sign());
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

    /**
     * The resulting signature is encoded as follows:
     * <p>
     * string    "signature_name"
     * string    signature_blob
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-6.6">
     * RFC 4253 SSH Transport Layer Protocol, section 6.6.</a>
     */
    @NonNull
    byte[] wrap(@NonNull final byte[] signature_blob) {
        // use a fixed-size buffer
        // (+4: a uint32 to store the length of the argument string)
        final Buffer buffer = new Buffer(4 + hostKeyAlgorithm.length()
                                                 + 4 + signature_blob.length)
                .putString(hostKeyAlgorithm)
                .putString(signature_blob);

        return buffer.data;
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

        }
        return sig;
    }
}
