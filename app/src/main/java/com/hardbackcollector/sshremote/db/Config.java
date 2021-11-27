package com.hardbackcollector.sshremote.db;

import static androidx.room.ForeignKey.CASCADE;

import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.ForeignKey;
import androidx.room.Ignore;
import androidx.room.PrimaryKey;

@SuppressWarnings("WeakerAccess")
@Entity(tableName = "host_command",
        foreignKeys = {
                @ForeignKey(entity = Host.class,
                        onDelete = CASCADE,
                        parentColumns = "_id",
                        childColumns = "host_id"),
                @ForeignKey(entity = Command.class,
                        onDelete = CASCADE,
                        parentColumns = "_id",
                        childColumns = "command_id")
        })
public class Config {

    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = "_id")
    public int id;

    @ColumnInfo(name = "position")
    public int position;

    @ColumnInfo(name = "name")
    public String label;

    @ColumnInfo(name = "host_id")
    public int hostId;
    @ColumnInfo(name = "command_id")
    public int commandId;

    public Config() {
    }

    @Ignore
    public Config(final int position) {
        this.position = position;
        this.label = "";
    }
}
