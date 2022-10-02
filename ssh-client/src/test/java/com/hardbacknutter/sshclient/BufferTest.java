package com.hardbacknutter.sshclient;


import static org.junit.jupiter.api.Assertions.assertEquals;

import com.hardbacknutter.sshclient.hostkey.HostKey;
import com.hardbacknutter.sshclient.utils.Buffer;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

class BufferTest {

    @Test
    void bla()
            throws IOException {
        final Buffer buffer = new Buffer();

        buffer.putByte((byte) 4)

                .putInt(123456)
                .putInt(-123456)

                .putInt(Integer.MAX_VALUE)
                .putInt(Integer.MAX_VALUE - 10)
                .putInt(Integer.MIN_VALUE)
                .putInt(Integer.MIN_VALUE + 10)

                .putLong(1L)
                .putLong(1_000_000_000_000_000_000L);

        // force overflow; pretending to be an unsigned int
        //noinspection NumericOverflow
        buffer.putInt(2_147_483_647 + 353)
                .putInt(2_147)

                .putString("Hello world");

        buffer.reset();
        assertEquals((byte) 4, buffer.getByte());
        assertEquals(123456, buffer.getInt());
        assertEquals(-123456, buffer.getInt());

        assertEquals(Integer.MAX_VALUE, buffer.getInt());
        assertEquals(Integer.MAX_VALUE - 10, buffer.getInt());
        assertEquals(Integer.MIN_VALUE, buffer.getInt());
        assertEquals(Integer.MIN_VALUE + 10, buffer.getInt());

        assertEquals(1L, buffer.getLong());
        assertEquals(1_000_000_000_000_000_000L, buffer.getLong());


        assertEquals(2_147_484_000L, buffer.getUInt());
        assertEquals(2_147, buffer.getUInt());
        assertEquals("Hello world", buffer.getJString());
    }

    @Test
    void fp()
            throws NoSuchAlgorithmException {
        final byte[] bytes = {1, 2, 3, 15, 16, 17};

        final String s = HostKey.getFingerPrint("MD5", bytes);

        assertEquals("12:c4:67:59:25:2f:d6:23:a9:96:d2:07:78:10:a3:b0", s);
        System.out.println(s);
    }
}
