package com.hardbackcollector.sshremote.db;

import androidx.annotation.Nullable;
import androidx.room.Dao;
import androidx.room.Delete;
import androidx.room.Insert;
import androidx.room.Query;
import androidx.room.Update;

import java.util.List;

@Dao
public interface ConfigDao {

    @Query("SELECT * FROM host_command")
    @Nullable
    List<Config> getAll();

    @Query("SELECT * FROM host_command WHERE _id=:id")
    @Nullable
    Config findById(int id);

    @Query("SELECT * FROM host_command WHERE position=:position")
    @Nullable
    Config findByPosition(int position);

    @Insert
    long insert(Config config);

    @Update
    void update(Config config);

    @Delete
    void delete(Config config);
}
