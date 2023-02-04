package com.hardbacknutter.sshclient.kex;

import androidx.annotation.NonNull;

import java.util.List;

public class KexNegotiationException
        extends KexException {

    private static final long serialVersionUID = 2587934441924170495L;
    @NonNull
    private final String type;
    @NonNull
    private final String server;
    @NonNull
    private final List<String> client;

    KexNegotiationException(@NonNull final String type,
                            @NonNull final String server,
                            @NonNull final List<String> client) {
        super(type);
        this.type = type;
        this.server = server;
        this.client = client;
    }

    @Override
    public String getMessage() {
        return "Algorithm negotiation failed: "
                + type
                + "|server=" + server
                + "|client=" + String.join(",", client);
    }

    @NonNull
    public String getType() {
        return type;
    }

    @NonNull
    public String getServer() {
        return server;
    }

    @NonNull
    public List<String> getClient() {
        return client;
    }
}
