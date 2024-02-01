package com.hardbacknutter.sshclient.transport;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import javax.crypto.Cipher;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.ciphers.AEADCipher;
import com.hardbacknutter.sshclient.ciphers.ChaChaCipher;
import com.hardbacknutter.sshclient.compression.SshInflater;
import com.hardbacknutter.sshclient.kex.KexAgreement;
import com.hardbacknutter.sshclient.macs.SshMac;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;
import com.hardbacknutter.sshclient.utils.Util;

public class TransportS2C
        extends Transport {

    private static final String ERROR_SOCKET_INPUT_STREAM_IS_NULL =
            "socketInputStream is null";
    private static final String ERROR_CONNECTION_CLOSED =
            "Connection is closed by foreign host";

    private static final String ERROR_MAX_PACKET_LEN_EXCEEDED =
            "Maximum Packet Length exceeded";
    private static final String ERROR_PACKET_LEN_INVALID =
            "Packet length must be multiple of cipher block-size, but was: ";

    private static final String ERROR_MAC_BLOCK_SIZE_MISMATCH = "MAC block-size mismatch";
    private static final String ERROR_HMAC_IS_NOT_SET = "MAC is not set";

    @Nullable
    private InputStream socketInputStream;
    @Nullable
    private SshInflater inflater;

    TransportS2C(@NonNull final Session session,
                 @NonNull final InputStream socketInputStream) {
        super(session, Cipher.DECRYPT_MODE);
        this.socketInputStream = socketInputStream;
    }

    /**
     * Read the server version.
     * This method must be called immediately after {@link TransportC2S#writeVersion(String)}
     * is called.
     *
     * @see TransportC2S#writeVersion(String)
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-4.2">
     * This identification string MUST be SSH-protoversion-softwareversion
     * SP comments CR LF</a>
     */
    @NonNull
    String readVersion()
            throws IOException {
        // Read the response; don't close the stream....
        //noinspection ConstantConditions
        final BufferedReader reader = new BufferedReader(
                new InputStreamReader(socketInputStream, StandardCharsets.UTF_8));

        String version;
        // The server MAY send other lines of data before sending the version
        //    string.  Each line SHOULD be terminated by a Carriage Return and Line
        //    Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
        //    in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
        //    MUST be able to process such lines.  Such lines MAY be silently
        //    ignored, or MAY be displayed to the client user.
        do {
            version = reader.readLine();
        } while (version != null && !version.startsWith("SSH-"));

        if (version == null) {
            throw new IOException("No server version received");
        }

        if (version.startsWith("SSH-1.99") || version.startsWith("SSH-2.0")) {
            return version;
        }

        throw new IOException("Invalid server's version string: " + version);
    }

    @Override
    void initCompression(@NonNull final KexAgreement agreement,
                         final boolean authenticated)
            throws IOException, NoSuchAlgorithmException {
        if (inflater == null) {
            inflater = ImplementationFactory.getInflater(
                    config, authenticated, agreement.getCompression(Cipher.DECRYPT_MODE));
        }
    }

    /**
     * Read the packet data from the InputStream, and decode it.
     */
    public void read(@NonNull final Packet packet)
            throws IOException, GeneralSecurityException {
        packet.reset();

        if (isChaCha()) {
            decodeChaCha(packet);
        } else if (isAEAD()) {
            decodeAEAD(packet);
        } else if (isEtM()) {
            decodeEtM(packet);
        } else {
            decodeMtE(packet);
        }

        if (inflater != null) {
            inflater.decompress(packet);
        }

        seq++;
    }

    private void decodeChaCha(@NonNull final Packet packet)
            throws IOException, GeneralSecurityException {

        Objects.requireNonNull(cipher, ERROR_CIPHER_IS_NOT_SET);
        Objects.requireNonNull(socketInputStream, ERROR_SOCKET_INPUT_STREAM_IS_NULL);

        // read ONLY the first 4 bytes, so we can get the length of the packet
        // the length field is encrypted!
        if (4 != socketInputStream.read(packet.data, 0, 4)) {
            throw new IOException(ERROR_CONNECTION_CLOSED);
        }
        packet.moveWritePosition(4);

        // init cipher with seq number
        ((ChaChaCipher) cipher).update(seq);

        // decrypt packet length field
        final byte[] tmp = new byte[4];
        cipher.update(packet.data, 0, 4, tmp, 0);
        int packetLen = ((tmp[0] << 24) & 0xff000000) |
                ((tmp[1] << 16) & 0x00ff0000) |
                ((tmp[2] << 8) & 0x0000ff00) |
                ((tmp[3]) & 0x000000ff);

        if (packetLen < 5 || packetLen > Packet.MAX_SIZE) {
            discard(packet, packetLen, Packet.MAX_SIZE);
            throw new IOException(ERROR_MAX_PACKET_LEN_EXCEEDED);
        }

        packetLen += ((AEADCipher) cipher).getTagSizeInBytes();

        // Resize the packet buffer if needed
        packet.ensureCapacity(packetLen);

        if ((packetLen % cipher.getBlockSize()) != 0) {
            discard(packet, packetLen, Packet.MAX_SIZE - 4);
            throw new IOException(ERROR_PACKET_LEN_INVALID + packetLen);
        }

        // Now we can read the actual full packet
        read(packet.data, packet.writeOffset, packetLen);

        // subtract tag size now that whole packet has been fetched
        packetLen -= ((AEADCipher) cipher).getTagSizeInBytes();

        packet.moveWritePosition(packetLen);

        try {
            cipher.doFinal(packet.data, 0, packetLen + 4, packet.data, 0);
        } catch (final GeneralSecurityException e) {
            discard(packet, packetLen, Packet.MAX_SIZE - packetLen);
            throw e;
        }

        // overwrite encrypted packet length field with decrypted version
        System.arraycopy(tmp, 0, packet.data, 0, 4);
    }

    private void decodeAEAD(@NonNull final Packet packet)
            throws IOException, GeneralSecurityException {

        Objects.requireNonNull(cipher, ERROR_CIPHER_IS_NOT_SET);
        Objects.requireNonNull(socketInputStream, ERROR_SOCKET_INPUT_STREAM_IS_NULL);

        // read ONLY the first 4 bytes, so we can get the length of the packet
        if (4 != socketInputStream.read(packet.data, 0, 4)) {
            throw new IOException(ERROR_CONNECTION_CLOSED);
        }
        packet.moveWritePosition(4);

        int packetLen = packet.getPacketLength();
        if (packetLen < 5 || packetLen > Packet.MAX_SIZE) {
            discard(packet, packetLen, Packet.MAX_SIZE);
            throw new IOException(ERROR_MAX_PACKET_LEN_EXCEEDED);
        }

        packetLen += ((AEADCipher) cipher).getTagSizeInBytes();

        // Resize the packet buffer if needed
        packet.ensureCapacity(packetLen);

        if ((packetLen % cipher.getBlockSize()) != 0) {
            discard(packet, packetLen, Packet.MAX_SIZE - 4);
            throw new IOException(ERROR_PACKET_LEN_INVALID + packetLen);
        }

        // Now we can read the actual full packet
        read(packet.data, packet.writeOffset, packetLen);
        packet.moveWritePosition(packetLen);

        try {
            cipher.updateAAD(packet.data, 0, 4);
            cipher.doFinal(packet.data, 4, packetLen, packet.data, 4);
        } catch (final GeneralSecurityException e) {
            discard(packet, packetLen, Packet.MAX_SIZE - packetLen);
            throw e;
        }

        // Move the position in the packet buffer back by the AEAD tag size,
        // so that decompression (if enabled) will work
        // (in case you missed it: there is a negative sign here)
        packet.moveWritePosition(-((AEADCipher) cipher).getTagSizeInBytes());
    }

    private void decodeEtM(@NonNull final Packet packet)
            throws IOException, GeneralSecurityException {

        Objects.requireNonNull(cipher, ERROR_CIPHER_IS_NOT_SET);
        Objects.requireNonNull(mac, ERROR_HMAC_IS_NOT_SET);
        Objects.requireNonNull(socketInputStream, ERROR_SOCKET_INPUT_STREAM_IS_NULL);

        // read ONLY the first 4 bytes, so we can get the length of the packet
        if (4 != socketInputStream.read(packet.data, 0, 4)) {
            throw new IOException(ERROR_CONNECTION_CLOSED);
        }
        packet.moveWritePosition(4);

        final int packetLen = packet.getPacketLength();
        if (packetLen < 5 || packetLen > Packet.MAX_SIZE) {
            discard(packet, packetLen, Packet.MAX_SIZE);
            throw new IOException(ERROR_MAX_PACKET_LEN_EXCEEDED);
        }

        // Resize the packet buffer if needed
        packet.ensureCapacity(packetLen);

        if ((packetLen % cipher.getBlockSize()) != 0) {
            discard(packet, packetLen, Packet.MAX_SIZE - 4);
            throw new IOException(ERROR_PACKET_LEN_INVALID + packetLen);
        }

        read(packet.data, packet.writeOffset, packetLen);
        packet.moveWritePosition(packetLen);

        mac.update(seq);
        mac.update(packet.data, 0, packet.writeOffset);

        final byte[] b1 = new byte[mac.getDigestLength()];
        final byte[] b2 = new byte[mac.getDigestLength()];

        mac.doFinal(b1, 0);

        read(b2, 0, b2.length);
        if (!Util.arraysEquals(b1, b2)) {
            discard(packet, packetLen, Packet.MAX_SIZE - packetLen);
            throw new IOException(ERROR_MAC_BLOCK_SIZE_MISMATCH);
        }
        cipher.update(packet.data, 4, packetLen, packet.data, 4);
    }

    private void decodeMtE(@NonNull final Packet packet)
            throws IOException, GeneralSecurityException {

        Objects.requireNonNull(socketInputStream, ERROR_SOCKET_INPUT_STREAM_IS_NULL);

        // Read one block (or 8 bytes if we don't have a cipher yet)
        // This is enough to read the actual packet length
        final int blockSize = cipher != null ? cipher.getBlockSize() : 8;
        if (blockSize != socketInputStream.read(packet.data, 0, blockSize)) {
            throw new IOException(ERROR_CONNECTION_CLOSED);
        }
        packet.moveWritePosition(blockSize);

        if (cipher != null) {
            cipher.update(packet.data, 0, blockSize, packet.data, 0);
        }

        final int packetLen = packet.getPacketLength();
        if (packetLen < 5 || packetLen > Packet.MAX_SIZE) {
            discard(packet, packetLen, Packet.MAX_SIZE);
            throw new IOException(ERROR_MAX_PACKET_LEN_EXCEEDED);
        }

        final int remaining = packetLen + 4 - blockSize;
        // Resize the packet buffer if needed
        packet.ensureCapacity(remaining);

        if (remaining % blockSize != 0) {
            discard(packet, packetLen, Packet.MAX_SIZE - blockSize);
            throw new IOException(ERROR_PACKET_LEN_INVALID + packetLen);
        }

        if (remaining > 0) {
            // read the rest of the packet
            read(packet.data, packet.writeOffset, remaining);
            packet.moveWritePosition(remaining);
            if (cipher != null) {
                cipher.update(packet.data, blockSize, remaining, packet.data, blockSize);
            }
        }

        if (mac != null) {
            mac.update(seq);
            mac.update(packet.data, 0, packet.writeOffset);

            final byte[] b1 = new byte[mac.getDigestLength()];
            final byte[] b2 = new byte[mac.getDigestLength()];

            mac.doFinal(b1, 0);

            read(b2, 0, b2.length);
            if (!Util.arraysEquals(b1, b2)) {
                if (remaining > Packet.MAX_SIZE) {
                    throw new IOException(ERROR_MAC_BLOCK_SIZE_MISMATCH);
                }
                discard(packet, packetLen, Packet.MAX_SIZE - remaining);
                throw new IOException(ERROR_MAC_BLOCK_SIZE_MISMATCH);
            }
        }
    }

    /**
     * From the JDK docs of {@link InputStream#read(byte[], int, int)}:
     * <pre>
     *     Reads up to len bytes of data from the input stream into an array of bytes.
     *     An attempt is made to read as many as len bytes, but a smaller number may be read.
     *     The number of bytes actually read is returned as an integer.
     * </pre>
     */
    private void read(@NonNull final byte[] bytes,
                      int offset,
                      int length)
            throws IOException {

        Objects.requireNonNull(socketInputStream, ERROR_SOCKET_INPUT_STREAM_IS_NULL);

        while (length > 0) {
            final int bytesRead = socketInputStream.read(bytes, offset, length);
            if (bytesRead < 0) {
                throw new IOException(ERROR_CONNECTION_CLOSED);
            }
            offset += bytesRead;
            length -= bytesRead;
        }
    }

    private void discard(@NonNull final Packet packet,
                         final int packetLen,
                         int nrOfBytes)
            throws IOException, GeneralSecurityException {

        if (packetLen == 0) {
            return;
        }

        if (cipher == null || !cipher.isMode("CBC")) {
            throw new IOException("Packet corrupt: cipher is not in CBC mode");
        }

        final SshMac discardingMac;
        if (packetLen != Packet.MAX_SIZE && mac != null) {
            discardingMac = mac;
        } else {
            discardingMac = null;
        }

        nrOfBytes -= packet.writeOffset;

        while (nrOfBytes > 0) {
            packet.reset();
            final int len = Math.min(nrOfBytes, packet.data.length);
            read(packet.data, 0, len);
            if (discardingMac != null) {
                discardingMac.update(packet.data, 0, len);
            }
            nrOfBytes -= len;
        }

        if (discardingMac != null) {
            discardingMac.doFinal(packet.data, 0);
        }
    }

    public void disconnect() {
        try {
            if (socketInputStream != null) {
                socketInputStream.close();
            }
            socketInputStream = null;
        } catch (@NonNull final Exception ignore) {
        }
    }
}
