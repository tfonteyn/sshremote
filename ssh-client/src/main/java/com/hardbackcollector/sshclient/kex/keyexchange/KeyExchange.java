package com.hardbackcollector.sshclient.kex.keyexchange;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.transport.Packet;
import com.hardbackcollector.sshclient.transport.PacketIO;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public interface KeyExchange {

    /**
     * constant used by {@link #getNextPacketExpected} when no more key exchange
     * packet is expected.
     */
    byte STATE_END = 0;

    /**
     * Initialises the class needed for the agreement.
     *
     * @throws GeneralSecurityException if initialising the class instance fails somehow
     */
    void initKeyAgreement(@NonNull SshClientConfig config)
            throws GeneralSecurityException;

    /**
     * Initializes the key exchange object.
     *
     * @param io  used to send packets
     * @param V_S the server's identification string sent before negotiation
     * @param V_C the client's identification string sent before negotiation
     * @param I_S the server's SSH_MSG_KEXINIT payload.
     * @param I_C the client's SSH_MSG_KEXINIT payload.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-7">
     * RFC 4253 SSH Transport Layer Protocol, 7. Key Exchange</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-8">
     * RFC 4253 SSH Transport Layer Protocol, 8. Diffie-Hellman Key Exchange</a>
     */
    void init(@NonNull SshClientConfig config,
              @NonNull PacketIO io,
              @NonNull byte[] V_S,
              @NonNull byte[] V_C,
              @NonNull byte[] I_S,
              @NonNull byte[] I_C)
            throws GeneralSecurityException, IOException;

    /**
     * Does the next step in the key exchange algorithm.
     * <p>
     * The received packet should have the same message-type as
     * {@link #getNextPacketExpected} returned before or this method will throw
     *
     * @param receivedPacket the received packet
     */
    void next(@NonNull Packet receivedPacket)
            throws GeneralSecurityException, IOException;

    /**
     * returns the identifier of the next SSH packet expected,
     * or {@link KeyExchange#STATE_END} if the KeyExchange was already
     * successfully finished.
     */
    byte getNextPacketExpected();

    /**
     * Check if the given command matches what we expect.
     *
     * @param command to check
     *
     * @return {@code true} if they match
     */
    boolean isExpecting(byte command);

    /**
     * Returns K_S, the server's public host key.
     *
     * @return an ssh string
     */
    @NonNull
    byte[] getK_S();

    /**
     * Returns K, the shared secret:
     *
     * @return an ssh mpint
     */
    @NonNull
    byte[] getK();

    /**
     * Returns H, the hash.
     */
    @NonNull
    byte[] getH();

    @NonNull
    MessageDigest getMessageDigest();

    /**
     * Is set AFTER the full exchange was successful
     *
     * @return the Server HostKey algorithm
     */
    @NonNull
    String getHostKeyAlgorithm();
}
