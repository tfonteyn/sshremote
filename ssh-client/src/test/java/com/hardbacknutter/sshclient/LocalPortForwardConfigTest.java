package com.hardbacknutter.sshclient;

import static org.junit.jupiter.api.Assertions.assertEquals;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.forwarding.LocalForwardConfig;
import com.hardbacknutter.sshclient.forwarding.PortForwardException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

class LocalPortForwardConfigTest {

    private static Stream<Arguments> sshConfigs() {
        return Stream.of(
                Arguments.of("bind_address:42:host:99", "bind_address", "host", 99, null),// colon
                Arguments.of("bind_address:42 host:99", "bind_address", "host", 99, null),// blank
                Arguments.of("42:host:99", null, "host", 99, null),// colon wo bind
                Arguments.of("42 host:99", null, "host", 99, null),// blank wo bind
                Arguments.of("localhost:42 host:99", "127.0.0.1", "host", 99, null),// blank
                Arguments.of(":42 host:99", "0.0.0.0", "host", 99, null),// bind is empty
                Arguments.of("*:42 host:99", "0.0.0.0", "host", 99, null),// bind is asterisk
                Arguments.of("bind_address:42 socket", "bind_address", null, -1, "socket"),// socket
                Arguments.of("42 socket", null, null, -1, "socket")// socket wo bind
        );
    }

    @ParameterizedTest
    @MethodSource("sshConfigs")
    void parseForwarding(@NonNull final String sshConfig,
                         final String expectedBindAddress,
                         final String expectedHost,
                         final int expectedHostPort,
                         final String expectedSocket)
            throws PortForwardException {

        final LocalForwardConfig localPortForwardConfig = LocalForwardConfig
                .parse(sshConfig);

        assertEquals(expectedBindAddress, localPortForwardConfig.bindAddress);
        assertEquals(42, localPortForwardConfig.port);
        assertEquals(expectedHost, localPortForwardConfig.host);
        assertEquals(expectedHostPort, localPortForwardConfig.hostPort);
        assertEquals(expectedSocket, localPortForwardConfig.socketPath);
    }
}
