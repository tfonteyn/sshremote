/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package com.hardbackcollector.sshclient.compression;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.transport.Packet;

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
