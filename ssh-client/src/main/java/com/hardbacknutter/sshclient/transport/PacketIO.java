package com.hardbacknutter.sshclient.transport;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.Session;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * This interface is used to decouple the IO methods from the {@link SessionImpl} object
 * for use by user-code. i.e. read/write is NOT provided on the {@link Session} interface
 * as users should not use it.
 * <p>
 * User-code will only need this when implementing custom channels or custom classes to replace
 * the default implementations.
 */
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
