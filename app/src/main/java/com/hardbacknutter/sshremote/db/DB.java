package com.hardbacknutter.sshremote.db;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

@Database(entities = {Host.class,
        Command.class,
        Config.class},
        version = 1)
public abstract class DB
        extends RoomDatabase {

    private static final String DB_NAME = "sshremote.db";

    private static volatile DB instance;

    private final Executor executor = Executors.newSingleThreadExecutor();

    @NonNull
    public static synchronized DB getInstance(@NonNull final Context context) {
        if (instance == null) {
            instance = create(context);
        }
        return instance;
    }

    @NonNull
    private static DB create(@NonNull final Context context) {
        return Room.databaseBuilder(
                context.getApplicationContext(),
                DB.class,
                DB_NAME).build();
    }

    @NonNull
    public Executor getExecutor() {
        return executor;
    }

    public abstract HostDao getHostDao();

    public abstract CommandDao getCommandDao();

    public abstract ConfigDao getConfigDao();
}
