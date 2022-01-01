package com.hardbackcollector.sshclient.compression;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.transport.Packet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Implementation using the native JDK java.util.zip classes.
 * {@link Deflater#SYNC_FLUSH} was introduced in Java 7.
 */
public class SshInflaterImpl
        implements SshInflater {

    private final byte[] tmpBuf = new byte[4096];

    private Inflater inflater;

    @Override
    public void init() {
        inflater = new Inflater();
    }

    @Override
    public void decompress(@NonNull final Packet packet)
            throws IOException {

        // * 2 is likely overkill, but lets be optimistic about the compression rate.
        final ByteArrayOutputStream outputStream =
                new ByteArrayOutputStream(packet.data.length * 2);

        final int len = packet.writeOffset - Packet.HEADER_LEN - packet.getPaddingLength();
        inflater.setInput(packet.data, Packet.HEADER_LEN, len);

        try {
            while (!inflater.finished()) {
                final int count = inflater.inflate(tmpBuf, 0, tmpBuf.length);
                if (count == 0) {
                    break;
                }
                outputStream.write(tmpBuf, 0, count);
            }
        } catch (final DataFormatException e) {
            throw new IOException(e);
        }

        outputStream.close();

        packet.setWriteOffSet(Packet.HEADER_LEN)
              .putBytes(outputStream.toByteArray());
    }
}
