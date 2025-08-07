package com.hardbacknutter.sshclient.transport;

import java.io.IOException;
import java.security.GeneralSecurityException;

import com.hardbacknutter.sshclient.Session;

import org.jspecify.annotations.NonNull;

/**
 * Read/write is NOT provided on the {@link Session} interface
 * as users should not use it for anything related to the session itself.
 * <p>
 * User-code will only need this when implementing custom channels or custom classes to replace
 * a default implementation.
 */
public interface PacketIO {

    /**
     * Read from the input (remote host) and return the resulting Packet.
     *
     * @return the Packet.
     *
     * @throws IOException              for generic IO errors
     * @throws GeneralSecurityException for generic security errors
     */
    @NonNull
    Packet read()
            throws IOException, GeneralSecurityException;

    /**
     * Send the given packet to the remote host.
     *
     * @param packet to send
     *
     * @throws IOException              for generic IO errors
     * @throws GeneralSecurityException for generic security errors
     */
    void write(@NonNull Packet packet)
            throws IOException, GeneralSecurityException;
}
