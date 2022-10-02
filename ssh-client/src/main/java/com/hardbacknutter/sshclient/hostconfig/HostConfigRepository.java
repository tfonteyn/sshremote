package com.hardbacknutter.sshclient.hostconfig;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.SshClient;

/**
 * A repository for host-specific configuration settings, retrievable by
 * host name (or an alias).
 * This can be implemented by an application and passed to
 * {@link SshClient#setHostConfigRepository(HostConfigRepository)}.
 */
public interface HostConfigRepository {

    /**
     * Returns the configuration for a specific host name (or host name alias).
     *
     * @param hostOrAlias The host or host-alias name.
     *                    When passing in {@code ""}, the repository should
     *                    return the global/default settings.
     *
     * @return the desired host configuration
     */
    @NonNull
    HostConfig getHostConfig(@NonNull String hostOrAlias);
}
