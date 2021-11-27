package com.hardbackcollector.sshclient.transport;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface PacketIO {

    /**
     * Read from the input (remote host) and return the resulting Packet.
     *
     * @return the Packet.
     */
    @NonNull
    Packet read()
            throws IOException, GeneralSecurityException;

    /**
     * Send the given packet to the remote host.
     *
     * @param packet to send
     */
    void write(@NonNull Packet packet)
            throws IOException, GeneralSecurityException;
}
