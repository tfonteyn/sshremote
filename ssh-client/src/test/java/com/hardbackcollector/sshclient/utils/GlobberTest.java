package com.hardbackcollector.sshclient.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import androidx.annotation.NonNull;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

class GlobberTest {

    private static final Map<String, String> m = Map.of(
            "", "",

            "test*/by? some* and another ? char",
            "test\\*/by\\? some\\* and another \\? char",

            "test*/by??? some* and another *?* char",
            "test\\*/by\\?\\?\\? some\\* and another \\*\\?\\* char",

            "\\", "\\\\",
            "\\\\ *", "\\\\\\\\ \\*"
    );

    /**
     * The original byte[] based algorithms from jsch.
     * Any changes to the {@link Globber} String based algorithms should be tested against these.
     */
    @NonNull
    private static String unquote_with_bytes(@NonNull final String path) {
        final byte[] _path = path.getBytes(StandardCharsets.UTF_8);
        final byte[] _uPath = unquote_with_bytes(_path);

        if (_path.length == _uPath.length) {
            return path;
        }
        return new String(_uPath, 0, _uPath.length, StandardCharsets.UTF_8);
    }

    @NonNull
    private static byte[] unquote_with_bytes(@NonNull final byte[] path) {
        int originalPathLength = path.length;

        int i = 0;
        while (i < originalPathLength) {
            if (path[i] == '\\') {
                if (i + 1 == originalPathLength) {
                    break;
                }
                System.arraycopy(path, i + 1, path, i, path.length - (i + 1));
                originalPathLength--;
            }
            i++;
        }

        if (originalPathLength == path.length) {
            return path;
        }
        final byte[] tmpPath = new byte[originalPathLength];
        System.arraycopy(path, 0, tmpPath, 0, originalPathLength);
        return tmpPath;
    }

    @NonNull
    private static String quote_with_bytes(@NonNull final String path) {
        final byte[] _path = path.getBytes(StandardCharsets.UTF_8);
        int count = 0;
        for (final byte b : _path) {
            if (b == '\\' || b == '?' || b == '*') {
                count++;
            }
        }
        if (count == 0) {
            return path;
        }
        final byte[] _path2 = new byte[_path.length + count];
        for (int i = 0, j = 0; i < _path.length; i++) {
            final byte b = _path[i];
            if (b == '\\' || b == '?' || b == '*') {
                _path2[j++] = '\\';
            }
            _path2[j++] = b;
        }
        return new String(_path2, 0, _path2.length, StandardCharsets.UTF_8);
    }

    @Test
    void quoting() {
        m.forEach((in, out) -> {
            final String quoted = Globber.quote(in);
            final String quoted_wb = quote_with_bytes(in);
            assertEquals(quoted, quoted_wb, "in: <" + in + ">\n" +
                    "string: <" + quoted + ">\nbytes: <" + quoted_wb + ">\n");

            final String unquoted = Globber.unquote(quoted);
            final String unquoted_wb = unquote_with_bytes(quoted_wb);
            assertEquals(unquoted, unquoted_wb, "in: <" + in + ">\n" +
                    "string: <" + unquoted + ">\nbytes: <" + unquoted_wb + ">\n");

            assertEquals(in, unquoted, "in: <" + in + ">\nbytes: <" + unquoted + ">\n");
            assertEquals(in, unquoted_wb, "in: <" + in + ">\nbytes: <" + unquoted_wb + ">\n");
        });
    }
}
