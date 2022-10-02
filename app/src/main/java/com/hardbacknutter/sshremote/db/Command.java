package com.hardbacknutter.sshremote.db;

import androidx.annotation.NonNull;
import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.Ignore;
import androidx.room.PrimaryKey;

@SuppressWarnings("WeakerAccess")
@Entity(tableName = "command")
public class Command {

    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = "_id")
    public int id;

    @ColumnInfo(name = "name")
    public String label;

    @ColumnInfo(name = "cmd_line")
    public String cmd;

    @ColumnInfo(name = "is_sudo")
    public boolean isSudo;
    @ColumnInfo(name = "sudo_pw")
    public String sudoPassword;

    public Command() {
        this("");
    }

    @Ignore
    public Command(@NonNull final String name) {
        this.label = name;
        cmd = "";
        isSudo = false;
        sudoPassword = "";
    }

    /**
     * Get the full commandline, including the sudo prefix if needed.
     *
     * @return exe
     */
    public String getCommandLine() {
        if (isSudo) {
            // man sudo
            //   -S  The -S (stdin) option causes sudo to read the password from the
            //       standard input instead of the terminal device.
            //   -p  The -p (prompt) option allows you to override the default
            //       password prompt and use a custom one.
            return "sudo -S -p '' " + cmd;
        } else {
            return cmd;
        }
    }
}
