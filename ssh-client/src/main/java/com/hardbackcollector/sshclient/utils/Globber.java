package com.hardbackcollector.sshclient.utils;

import androidx.annotation.NonNull;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public final class Globber {

    private static final boolean fs_is_bs = File.separatorChar == '\\';

    private Globber() {
    }

    /**
     * Check if the given path has <strong>un-escaped</strong> wildcards.
     *
     * @param path to check
     *
     * @return {@code true} if this path represents a pattern
     */
    public static boolean isPattern(@NonNull final String path) {
        final byte[] _path = path.getBytes(StandardCharsets.UTF_8);

        final int length = _path.length;
        int i = 0;
        while (i < length) {
            if (_path[i] == '*' || _path[i] == '?') {
                return true;
            }
            if (_path[i] == '\\' && i + 1 < length) {
                i++;
            }
            i++;
        }
        return false;
    }

    @NonNull
    public static List<String> globAbsoluteLocalPath(@NonNull final String absPath) {

        final byte[] pathBytes = absPath.getBytes(StandardCharsets.UTF_8);

        int i = pathBytes.length - 1;
        while (i >= 0) {
            if (pathBytes[i] != '*' && pathBytes[i] != '?') {
                i--;
                continue;
            }
            if (!fs_is_bs && i > 0 && pathBytes[i - 1] == '\\') {

                i--;
                if (i > 0 && pathBytes[i - 1] == '\\') {
                    i--;
                    i--;
                    continue;
                }
            }
            break;
        }

        if (i < 0) {
            final List<String> list = new ArrayList<>();
            list.add(fs_is_bs ? absPath : unquote(absPath));
            return list;
        }

        while (i >= 0) {
            // On Windows, both '\' and '/' can be used as the separator.
            if (pathBytes[i] == File.separatorChar || fs_is_bs && pathBytes[i] == '/') {
                break;
            }
            i--;
        }

        if (i < 0) {
            final List<String> list = new ArrayList<>();
            list.add(fs_is_bs ? absPath : unquote(absPath));
            return list;
        }

        final String dir;
        if (i == 0) {
            // root
            dir = File.separator;
        } else {
            dir = new String(pathBytes, 0, i, StandardCharsets.UTF_8);
        }

        final byte[] pattern = new byte[pathBytes.length - i - 1];
        System.arraycopy(pathBytes, i + 1, pattern, 0, pattern.length);

        final String[] children = new File(dir).list();
        if (children != null) {
            return Arrays.stream(children)
                         .filter(child -> glob(pattern, child.getBytes(StandardCharsets.UTF_8)))
                         .map(child -> dir + File.separatorChar + child)
                         .collect(Collectors.toList());

        }
        return new ArrayList<>();
    }

    /**
     * Pattern matching function which returns {@code true} if the specified pattern
     * matches the specified name.
     *
     * @return {@code true} if pattern matches name
     */
    public static boolean glob(@NonNull final byte[] pattern,
                               @NonNull final byte[] name) {
        if (name.length > 0 && name[0] == '.') {
            if (pattern.length > 0 && pattern[0] == '.') {
                if (pattern.length == 2 && pattern[1] == '*') {
                    return true;
                }
                return glob(pattern, 1, name, 1);
            }
            return false;
        }
        return glob(pattern, 0, name, 0);
    }

    /**
     * Pattern matching function which returns {@code true} if the specified pattern
     * matches the specified name starting from specified pattern index and
     * name index.
     *
     * @return {@code true} if pattern matches name from given indexes
     */
    private static boolean glob(@NonNull final byte[] pattern,
                                final int patternIndex,
                                @NonNull final byte[] name,
                                final int nameIndex) {

        final int pattern_len = pattern.length;
        if (pattern_len == 0) {
            return false;
        }

        final int name_len = name.length;
        int i = patternIndex;
        int j = nameIndex;

        while (i < pattern_len && j < name_len) {
            if (pattern[i] == '\\') {
                if (i + 1 == pattern_len) {
                    return false;
                }
                i++;
                if (pattern[i] != name[j]) {
                    return false;
                }
                i += skipUTF8Char(pattern[i]);
                j += skipUTF8Char(name[j]);
                continue;
            }

            if (pattern[i] == '*') {
                while (i < pattern_len && pattern[i] == '*') {
                    i++;
                }

                if (pattern_len == i) {
                    return true;
                }

                byte foo = pattern[i];
                if (foo == '?') {
                    while (j < name_len) {
                        if (glob(pattern, i, name, j)) {
                            return true;
                        }
                        j += skipUTF8Char(name[j]);
                    }
                    return false;
                } else if (foo == '\\') {
                    if (i + 1 == pattern_len) {
                        return false;
                    }
                    i++;
                    foo = pattern[i];
                    while (j < name_len) {
                        if (foo == name[j]) {
                            if (glob(pattern, i + skipUTF8Char(foo),
                                     name, j + skipUTF8Char(name[j]))) {
                                return true;
                            }
                        }
                        j += skipUTF8Char(name[j]);
                    }
                    return false;
                }

                while (j < name_len) {
                    if (foo == name[j]) {
                        if (glob(pattern, i, name, j)) {
                            return true;
                        }
                    }
                    j += skipUTF8Char(name[j]);
                }
                return false;
            }

            if (pattern[i] == '?') {
                i++;
                j += skipUTF8Char(name[j]);
                continue;
            }

            if (pattern[i] != name[j]) {
                return false;
            }

            i += skipUTF8Char(pattern[i]);
            j += skipUTF8Char(name[j]);

            if (!(j < name_len)) {         // name is end
                if (!(i < pattern_len)) {    // pattern is end
                    return true;
                }
                if (pattern[i] == '*') {
                    break;
                }
            }
        }

        if (i == pattern_len && j == name_len) {
            return true;
        }

        if (!(j < name_len) &&  // name is end
                pattern[i] == '*') {
            boolean ok = true;
            while (i < pattern_len) {
                if (pattern[i++] != '*') {
                    ok = false;
                    break;
                }
            }
            return ok;
        }

        return false;
    }

    private static int skipUTF8Char(final byte b) {
        if ((byte) (b & 0x80) == 0) {
            return 1;
        } else if ((byte) (b & 0xe0) == (byte) 0xc0) {
            return 2;
        } else if ((byte) (b & 0xf0) == (byte) 0xe0) {
            return 3;
        } else {
            return 1;
        }
    }

    @NonNull
    public static String unquote(@NonNull final String path) {
        final byte[] _path = path.getBytes(StandardCharsets.UTF_8);
        final byte[] _uPath = unquote(_path);

        if (_path.length == _uPath.length) {
            return path;
        }
        return new String(_uPath, 0, _uPath.length, StandardCharsets.UTF_8);
    }

    @NonNull
    public static byte[] unquote(@NonNull final byte[] path) {
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
    private static String quote(@NonNull final String path) {
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
}
