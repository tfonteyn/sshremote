package com.hardbacknutter.sshclient.transport;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import javax.crypto.Cipher;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.ciphers.AEADCipher;
import com.hardbacknutter.sshclient.ciphers.ChaChaCipher;
import com.hardbacknutter.sshclient.compression.SshDeflater;
import com.hardbacknutter.sshclient.kex.KexAgreement;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

public class TransportC2S
        extends Transport {

    @Nullable
    private OutputStream socketOutputStream;
    @Nullable
    private SshDeflater deflater;

    TransportC2S(@NonNull final Session session,
                 @NonNull final OutputStream socketOutputStream)
            throws NoSuchAlgorithmException {
        super(session, Cipher.ENCRYPT_MODE);
        this.socketOutputStream = socketOutputStream;
    }

    /**
     * Send our client version to the server. This is step one in the KEX process.
     *
     * @param clientVersion to send. Should NOT have any trailing cr/lf.
     *                      Those will be added here.
     *
     * @see TransportS2C#readVersion()
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-4.2">
     * This identification string MUST be SSH-protoversion-softwareversion
     * SP comments CR LF</a>
     */
    void writeVersion(@NonNull final String clientVersion)
            throws IOException {
        final byte[] C_V = (clientVersion + "\r\n").getBytes(StandardCharsets.UTF_8);
        //noinspection DataFlowIssue
        socketOutputStream.write(C_V, 0, C_V.length);
        socketOutputStream.flush();
    }

    @Override
    void initCompression(@NonNull final KexAgreement agreement,
                         final boolean authenticated)
            throws IOException, NoSuchAlgorithmException {
        if (deflater == null) {
            deflater = ImplementationFactory.getDeflater(
                    config, authenticated, agreement.getCompression(Cipher.ENCRYPT_MODE));
        }
    }

    /**
     * Unconditionally send the packet.
     * <p>
     * Compress the Packet (if enabled), encode it, and finally send it to the remote server.
     *
     * @param packet to handle
     */
    public synchronized void write(@NonNull final Packet packet)
            throws IOException, GeneralSecurityException {

        if (deflater != null) {
            deflater.compress(packet);
        }

        if (cipher == null) {
            // pre-kex, not encrypted, just add padding etc... and we're done
            packet.finish(8, true, config.getRandom());
        } else if (isChaCha()) {
            encodeChaCha(packet);
        } else if (isAEAD()) {
            encodeAEAD(packet);
        } else if (isEtM()) {
            encodeEtM(packet);
        } else {
            encodeMtE(packet);
        }

        if (socketOutputStream != null) {
            socketOutputStream.write(packet.data, 0, packet.writeOffset);
            socketOutputStream.flush();
        } else {
            throw new IOException("socketOutputStream closed/null");
        }

        seq++;
    }

    private void encodeChaCha(@NonNull final Packet packet)
            throws GeneralSecurityException {
        Objects.requireNonNull(cipher, ERROR_CIPHER_IS_NOT_SET);

        packet.finish(cipher.getBlockSize(), false, config.getRandom());
        // init cipher with seq number
        ((ChaChaCipher) cipher).update(seq);
        // encrypt packet length field
        cipher.update(packet.data, 0, 4, packet.data, 0);
        //encrypt rest of packet & add tag
        cipher.doFinal(packet.data, 0, packet.writeOffset, packet.data, 0);
        // adjust write offset
        packet.moveWritePosition(((ChaChaCipher) cipher).getTagSizeInBytes());
    }

    private void encodeAEAD(@NonNull final Packet packet)
            throws GeneralSecurityException {
        Objects.requireNonNull(cipher, ERROR_CIPHER_IS_NOT_SET);

        packet.finish(cipher.getBlockSize(), false, config.getRandom());
        // Authenticated Encryption with Additional Data
        cipher.updateAAD(packet.data, 0, 4);
        cipher.doFinal(packet.data, 4, packet.writeOffset - 4, packet.data, 4);
        // adjust write offset
        packet.moveWritePosition(((AEADCipher) cipher).getTagSizeInBytes());
    }

    private void encodeEtM(@NonNull final Packet packet) throws GeneralSecurityException {
        Objects.requireNonNull(cipher, ERROR_CIPHER_IS_NOT_SET);
        packet.finish(cipher.getBlockSize(), false, config.getRandom());
        // First Encrypt
        cipher.update(packet.data, 4, packet.writeOffset - 4, packet.data, 4);
        // then Mac
        //noinspection DataFlowIssue
        mac.update(seq);
        mac.update(packet.data, 0, packet.writeOffset);
        mac.doFinal(packet.data, packet.writeOffset);
        // adjust write offset
        packet.moveWritePosition(mac.getDigestLength());
    }

    private void encodeMtE(@NonNull final Packet packet) throws GeneralSecurityException {
        Objects.requireNonNull(cipher, ERROR_CIPHER_IS_NOT_SET);
        packet.finish(cipher.getBlockSize(), true, config.getRandom());
        // First Mac
        if (mac != null) {
            mac.update(seq);
            mac.update(packet.data, 0, packet.writeOffset);
            mac.doFinal(packet.data, packet.writeOffset);
        }
        // then Encrypt
        cipher.update(packet.data, 0, packet.writeOffset, packet.data, 0);

        // adjust write offset if we used a MAC
        if (mac != null) {
            packet.moveWritePosition(mac.getDigestLength());
        }
    }

    public void disconnect() {
        try {
            if (socketOutputStream != null) {
                socketOutputStream.close();
            }
            socketOutputStream = null;
        } catch (@NonNull final Exception ignore) {
        }
    }
}
