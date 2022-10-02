package com.hardbacknutter.sshremote.db;

import androidx.room.Dao;
import androidx.room.Delete;
import androidx.room.Insert;
import androidx.room.Query;
import androidx.room.Update;

import java.util.List;

@Dao
public interface CommandDao {

    @Query("SELECT * FROM command")
    List<Command> getAll();

    @Query("SELECT * FROM command WHERE _id=:id")
    Command findById(int id);

    @Insert
    long insert(Command command);

    @Update
    void update(Command command);

    @Delete
    void delete(Command command);
}
