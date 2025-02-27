package com.hardbacknutter.sshclient.kex;

import org.jspecify.annotations.NonNull;

class KexStrictViolationException
        extends KexException {
    private static final long serialVersionUID = 3429147121303439312L;

    KexStrictViolationException(@NonNull final String message) {
        super(message);
    }
}
