package com.hardbacknutter.sshclient.channels.forward;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.RemoteForwardingHandler;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SocketFactory;
import com.hardbacknutter.sshclient.channels.SshChannelException;
import com.hardbacknutter.sshclient.forwarding.LocalForwardConfig;
import com.hardbacknutter.sshclient.forwarding.PortForwardException;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.SessionImpl;
import com.hardbacknutter.sshclient.utils.SshConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Handles all remote port forwarding.
 * <p>
 * Has a 1:1 relation to an open Session.
 * <p>
 * Call {@link Session#getRemoteForwardingHandler()} to gain access.
 */
public class RemoteForwardingHandlerImpl
        implements RemoteForwardingHandler {

    /** All active forwards. */
    private static final List<RemoteForwardConfig> pool = new ArrayList<>();

    @NonNull
    private final SessionImpl session;
    private final GlobalRequestReply grr = new GlobalRequestReply();

    /**
     * Constructor.
     */
    public RemoteForwardingHandlerImpl(@NonNull final SessionImpl session) {
        this.session = session;
    }

    @NonNull
    private static String normalize(@Nullable final String address) {
        if (address == null) {
            return "localhost";
        } else if (address.isEmpty() || "*".equals(address)) {
            return "";
        } else {
            return address;
        }
    }

    @Nullable
    public static RemoteForwardConfig find(@NonNull final Session session,
                                           @Nullable final String bindAddress,
                                           final int remotePort) {
        synchronized (pool) {
            return pool.stream()
                       .filter(config -> session.equals(config.getSession()))
                       .filter(config -> (remotePort == config.getRemotePort()
                               ||
                               (0 == config.getRemotePort()
                                       && remotePort == config.getAllocatedRemotePort())))
                       .filter(config -> bindAddress == null
                               || bindAddress.equals(config.getBindAddress()))
                       .findFirst()
                       .orElse(null);
        }
    }


    @Override
    @NonNull
    public List<String> getList() {
        synchronized (pool) {
            return pool.stream()
                       .filter(c -> c.getSession().equals(session))
                       .map(RemoteForwardConfig::getAsString)
                       .collect(Collectors.toList());
        }
    }

    @Override
    public int add(@Nullable final String bindAddress,
                   final int remotePort,
                   @NonNull final String host,
                   final int localPort,
                   @Nullable final SocketFactory socketFactory)
            throws IOException, GeneralSecurityException, SshChannelException {

        final int allocated = sendForwardRequest(bindAddress, remotePort);
        add(bindAddress, remotePort, allocated, host, localPort, socketFactory);
        return allocated;
    }

    @Override
    public int add(@NonNull final String connectionString)
            throws IOException, GeneralSecurityException,
                   PortForwardException, SshChannelException {
        final LocalForwardConfig lfc = LocalForwardConfig.parse(connectionString);

        if (lfc.socketPath == null) {
            // Note we must reverse the meaning of the 'f' port/hostport parameters here
            final int allocated = sendForwardRequest(lfc.bindAddress, lfc.port);
            //noinspection ConstantConditions
            add(lfc.bindAddress, lfc.port, allocated, lfc.host, lfc.hostPort, null);
            return allocated;

        } else {
            throw new PortForwardException("local socket path not supported");
        }
    }

    private void add(@Nullable final String bindAddress,
                     final int remotePort,
                     final int allocated_port,
                     @NonNull final String host,
                     final int localPort,
                     @Nullable final SocketFactory socketFactory)
            throws SshChannelException {
        final String nBindAddress = normalize(bindAddress);
        synchronized (pool) {
            if (find(session, nBindAddress, remotePort) != null) {
                throw new SshChannelException("remote port " + remotePort
                                                      + " is already registered.");
            }
            pool.add(new RemoteForwardSocketConfig(session, remotePort, allocated_port,
                                                   nBindAddress,
                                                   host, localPort, socketFactory));
        }
    }

    @Override
    public int addDaemon(@Nullable final String bindAddress,
                         final int remotePort,
                         @NonNull final String className,
                         @Nullable final Object[] arg)
            throws IOException, GeneralSecurityException, SshChannelException {

        final int allocated = sendForwardRequest(bindAddress, remotePort);

        final String nBindAddress = normalize(bindAddress);

        synchronized (pool) {
            if (find(session, nBindAddress, remotePort) != null) {
                throw new SshChannelException("remote port " + remotePort
                                                      + " is already registered.");
            }
            pool.add(new RemoteForwardDaemonConfig(session, remotePort,
                                                   // original code uses remotePort here!!
                                                   remotePort,
                                                   nBindAddress, className, arg));
        }

        return allocated;
    }

    @Override
    public void remove(@Nullable String bindAddress,
                       final int remotePort) {
        synchronized (pool) {
            RemoteForwardConfig config = find(session, normalize(bindAddress), remotePort);
            if (config == null) {
                config = find(session, null, remotePort);
            }
            if (config == null) {
                return;
            }
            pool.remove(config);
            if (bindAddress == null) {
                bindAddress = config.getBindAddress();
            }
        }

        // byte     SSH_MSG_GLOBAL_REQUEST
        // string   "cancel-tcpip-forward"
        // boolean  want_reply
        // string   address_to_bind (e.g. "127.0.0.1")
        // uint32   port number to bind
        final Packet packet = new Packet(SshConstants.SSH_MSG_GLOBAL_REQUEST)
                .putString("cancel-tcpip-forward".getBytes(StandardCharsets.UTF_8))
                .putBoolean(false)
                .putString(bindAddress)
                .putInt(remotePort);
        try {
            session.write(packet);
        } catch (final Exception ignore) {
        }
    }

    /**
     * Request a remote Port Forwarding.
     * <p>
     * The 'address to bind' and 'port number to bind' specify the IP
     * address (or domain name) and port on which connections for forwarding
     * are to be accepted.
     *
     * @param address 'address to bind' on the remote host
     * @param port    'port number to bind' on the remote host
     *
     * @return the port that was bound on the server
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-7">
     * RFC 4254 SSH Connection Protocol, section 7. TCP/IP Port Forwarding</a>
     */
    private int sendForwardRequest(@Nullable final String address,
                                   final int port)
            throws IOException, GeneralSecurityException {

        final int allocatedPort;

        synchronized (grr) {

            final String bindAddress;
            if (address == null) {
                // "localhost" means to listen on all protocol families supported by
                // the SSH implementation on loopback addresses only
                bindAddress = "localhost";

            } else if (address.isEmpty() || "*".equals(address)) {
                // "" means that connections are to be accepted on all protocol
                // families supported by the SSH implementation.
                bindAddress = "";

            } else {
                bindAddress = address;
            }

            grr.setThread(Thread.currentThread());
            grr.setPort(port);

            try {
                // byte     SSH_MSG_GLOBAL_REQUEST
                // string   "tcpip-forward"
                // boolean  want_reply
                // string   address_to_bind
                // uint32   port number to bind
                final Packet packet = new Packet(SshConstants.SSH_MSG_GLOBAL_REQUEST)
                        .putString("tcpip-forward")
                        .putBoolean(true)
                        .putString(bindAddress)
                        .putInt(port);
                session.write(packet);
            } catch (final IOException | GeneralSecurityException e) {
                grr.setThread(null);
                throw e;
            }

            int count = 0;
            int reply = grr.getReply();
            while (count < 10 && reply == -1) {
                try {
                    Thread.sleep(1000);
                } catch (final Exception ignore) {
                }
                count++;
                reply = grr.getReply();
            }
            grr.setThread(null);
            if (reply != 1) {
                throw new IOException("remote port forwarding failed for listen port " + port);
            }
            allocatedPort = grr.getPort();
        }
        return allocatedPort;
    }

    /**
     * Called from the main session loop to handle success or failure messages.
     *
     * @param packet to handle
     */
    public void handleRemoteReply(@NonNull final Packet packet) {
        final Thread t = grr.getThread();
        if (t != null) {
            final byte command = packet.getCommand();
            grr.setReply(command == SshConstants.SSH_MSG_REQUEST_SUCCESS ? 1 : 0);
            if (command == SshConstants.SSH_MSG_REQUEST_SUCCESS && grr.getPort() == 0) {
                packet.startReadingPayload();
                packet.getByte(); // command
                grr.setPort(packet.getInt());
            }
            t.interrupt();
        }
    }

    /**
     * Called when the session is disconnected.
     */
    public void disconnect() {
        final List<Integer> portList;
        synchronized (pool) {
            portList = pool.stream()
                           .filter(config -> config.getSession().equals(session))
                           .map(RemoteForwardConfig::getRemotePort)
                           .collect(Collectors.toList());
        }
        // remove will also remove from pool
        portList.forEach(port -> remove(null, port));
    }

    /**
     * Maintains the state of a single global request and it's corresponding
     * reply from the SSH server for a requesting thread.  A single, final
     * instance is used to synchronize on to allow only one global request to be
     * handled at a time.
     * <p>
     * TODO SSH spec allows multiple global requests to be sent, responses are
     * guaranteed to return in the order they are requested... could use queue
     * to store requests and handle responses rather than blocking
     */
    private static class GlobalRequestReply {

        /**
         * Thread waiting for a reply from global request.
         */
        @Nullable
        private Thread thread;

        private int reply = -1;
        private int port;

        /**
         * Returns the thread waiting for a reply to a global request.
         *
         * @return thread waiting for reply
         */
        @Nullable
        Thread getThread() {
            return thread;
        }

        /**
         * Sets the thread making the global request which waits for a reply.
         *
         * @param thread making global request
         */
        void setThread(@Nullable final Thread thread) {
            this.thread = thread;
            this.reply = -1;
        }

        /**
         * Returns the reply to the global request returned by the SSH server.
         *
         * @return reply
         */
        int getReply() {
            return this.reply;
        }

        /**
         * Sets the reply to the global request returned by the SSH server.
         *
         * @param reply to set
         */
        void setReply(final int reply) {
            this.reply = reply;
        }

        int getPort() {
            return this.port;
        }

        void setPort(final int port) {
            this.port = port;
        }
    }
}
