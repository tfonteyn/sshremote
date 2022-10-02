package com.hardbacknutter.sshclient.compression;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.transport.Packet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;

/**
 * Implementation using the native JDK java.util.zip classes.
 * {@link Deflater#SYNC_FLUSH} was introduced in Java 7.
 */
public class SshDeflaterImpl
        implements SshDeflater {

    private final byte[] tmpBuf = new byte[4096];

    private Deflater deflater;

    @Override
    public void init(final int level) {
        deflater = new Deflater(level);
    }

    @Override
    public void compress(@NonNull final Packet packet)
            throws IOException {

        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream(packet.data.length);

        final int payloadLength = packet.writeOffset - Packet.HEADER_LEN;
        deflater.setInput(packet.data, Packet.HEADER_LEN, payloadLength);

        while (!deflater.finished()) {
            final int count = deflater.deflate(tmpBuf, 0, tmpBuf.length, Deflater.SYNC_FLUSH);
            if (count == 0) {
                break;
            }
            outputStream.write(tmpBuf, 0, count);
        }

        outputStream.close();

        packet.setWriteOffSet(Packet.HEADER_LEN)
              .putBytes(outputStream.toByteArray());
    }
}
