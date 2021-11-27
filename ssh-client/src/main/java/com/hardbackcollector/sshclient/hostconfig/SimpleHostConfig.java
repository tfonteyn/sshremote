package com.hardbackcollector.sshclient.hostconfig;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SimpleHostConfig
        implements HostConfigRepository.HostConfig {

    private final Map<String, String> config = new HashMap<>();
    @NonNull
    private final String host;
    @Nullable
    private final String username;
    private final int port;

    public SimpleHostConfig(@NonNull final String host,
                            final int port,
                            @Nullable final String username) {
        this.host = host;
        this.username = username;
        this.port = port;

        config.put(HOSTNAME, host);
        config.put(PORT, String.valueOf(port));
        if (username != null) {
            config.put(USER, username);
        }
    }

    @Nullable
    @Override
    public String getHostname() {
        return host;
    }

    @Nullable
    @Override
    public String getUser() {
        return username;
    }

    @Override
    public int getPort() {
        return port;
    }

    @Nullable
    @Override
    public String getString(@NonNull final String key) {
        return config.get(key);
    }

    @NonNull
    @Override
    public List<String> getStringList(@NonNull final String key) {
        final List<String> list = new ArrayList<>();

        final String value = getString(key);
        if (value != null) {
            list.add(value);
        }
        return list;
    }
}
