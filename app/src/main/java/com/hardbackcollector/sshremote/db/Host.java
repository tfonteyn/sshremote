package com.hardbackcollector.sshremote.db;

import androidx.annotation.NonNull;
import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.Ignore;
import androidx.room.PrimaryKey;

import com.hardbackcollector.sshremote.DNSService;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("WeakerAccess")
@Entity(tableName = "host")
public class Host {

    public static final int DEFAULT_PORT = 22;
    /**
     * Timeout for {@link #ping()}; connection to the DNS server.
     */
    private static final long DNS_TIMEOUT_MS = 5_000L;
    /**
     * Timeout for {@link #ping()}; connection to the host.
     */
    private static final int PING_TIMEOUT_MS = 5_000;
    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = "_id")
    public int id;

    @ColumnInfo(name = "name")
    public String label;

    @ColumnInfo(name = "hostname")
    public String hostnameOrIp;

    @ColumnInfo(name = "port")
    public int port;

    @ColumnInfo(name = "p_shkc")
    public boolean strictHostKeyChecking;

    @ColumnInfo(name = "user_name")
    public String userName;
    @ColumnInfo(name = "user_pw")
    public String userPassword;

    public Host() {
        this("");
    }

    @Ignore
    public Host(@NonNull final String label) {
        this.label = label;
        hostnameOrIp = "";
        port = DEFAULT_PORT;
        strictHostKeyChecking = false;
        userName = "";
        userPassword = "";
    }

    @NonNull
    public Map<String, String> getOptions() {
        final Map<String, String> props = new HashMap<>();
        props.put("StrictHostKeyChecking", strictHostKeyChecking ? "yes" : "no");
        return props;
    }

    public void ping()
            throws UnknownHostException {
        try {
            final InetAddress inetAddress = new DNSService().lookup(hostnameOrIp, DNS_TIMEOUT_MS);

            final Socket sock = new Socket();
            sock.connect(new InetSocketAddress(inetAddress, port), PING_TIMEOUT_MS);
            sock.close();
            return;
        } catch (final IOException ignore) {
        }

        throw new UnknownHostException(hostnameOrIp);
    }
}
