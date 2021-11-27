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
package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.channels.forward.ChannelForwardedTCPIP;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * A local daemon <em>{@link Runnable}</em> executed when a host connects to
 * to a forwarded port at the remote side.
 * <p>
 * An application should implement this interface if it wants to handle
 * such connections internally instead of forwarding them to another
 * host/port on the local side.
 * <p>
 * All implementations should provide a no-argument constructor, as this
 * one is used when creating an instance.
 * <p>
 * When someone connects to the remote socket we:
 * <ol>
 *     <li>Create an instance using the no-argument constructor</li>
 *     <li>call {@link #setArgs} with the arguments given when the channel was created.</li>
 *     <li>call {@link #setChannel} (with the streams connected to the remote socket)</li>
 *     <li>create a new Thread and start the {@link Runnable}</li>
 * </ol>
 *
 * @see RemoteForwardingHandler
 */
@SuppressWarnings("unused")
public interface ForwardedTCPIPDaemon
        extends Runnable {

    /**
     * Sets additional arguments given when the forwarding was created.
     *
     * @param args arguments to be used by the daemon, the meaning is application
     *             specific. This array MUST NOT be changed, as all subsequent
     *             daemons for this same port forwarding would be affected.
     */
    void setArgs(@Nullable Object[] args);

    /**
     * Sets the streams to be used for communication.
     * This method should not block (or try to read/write from/to these streams),
     * all interaction should be done in the {@link #run} method.
     *
     * @param channel the channel connected to the remote socket.
     *                This object may be used to disconnect, for example.
     * @param in      all data arriving from the remote socket can be read
     *                from this stream.
     * @param out     all data written to this stream will be sent to the
     *                remote socket.
     */
    void setChannel(@NonNull ChannelForwardedTCPIP channel,
                    @NonNull InputStream in,
                    @NonNull OutputStream out);

    /*
     * Does the actual connection handling. This method will be run in
     * an own thread (the others will be called from the channel's
     * {@link Channel#connect()}) and should close the channel
     * at the end (otherwise we will have a dangling connection,
     *  if the remote client host does not close it).
     */
    //void run();
}
