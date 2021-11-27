package com.hardbackcollector.sshremote;

class NotConfiguredException
        extends RuntimeException {

    private static final long serialVersionUID = 8564619713743945654L;

    public NotConfiguredException() {
    }

    public NotConfiguredException(final String message) {
        super(message);
    }
}
