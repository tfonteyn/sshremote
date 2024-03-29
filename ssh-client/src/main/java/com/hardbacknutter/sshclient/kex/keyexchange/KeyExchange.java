package com.hardbacknutter.sshclient.kex.keyexchange;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.PacketIO;

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
     *         RFC 4253 SSH Transport Layer Protocol, 7. Key Exchange</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-8">
     *         RFC 4253 SSH Transport Layer Protocol, 8. Diffie-Hellman Key Exchange</a>
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
     * Get K_S, the server's public host key.
     *
     * @return an ssh string
     */
    @NonNull
    byte[] getK_S();

    /**
     * Get K, the shared secret; as a raw byte[].
     * <p>
     * The format may be different (mpint, ssh-string,...) in individual implementations,
     * but <strong>MUST</strong> be returned as a raw byte[].
     *
     * @return the shared secret; as a raw byte[].
     */
    @NonNull
    byte[] getK();

    /**
     * Get H, the hash, as a raw byte[].
     *
     * @return H
     */
    @NonNull
    byte[] getH();

    /**
     * Get the hash generator as used during KEX.
     *
     * @return MessageDigest
     */
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
