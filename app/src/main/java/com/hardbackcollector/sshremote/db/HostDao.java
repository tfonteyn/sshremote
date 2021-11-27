package com.hardbackcollector.sshremote.db;

import androidx.room.Dao;
import androidx.room.Delete;
import androidx.room.Insert;
import androidx.room.Query;
import androidx.room.Update;

import java.util.List;

@Dao
public interface HostDao {

    @Query("SELECT * FROM host")
    List<Host> getAll();

    @Query("SELECT * FROM host WHERE _id=:id")
    Host findById(int id);

    @Insert
    long insert(Host host);

    @Update
    void update(Host host);

    @Delete
    void delete(Host host);
}
