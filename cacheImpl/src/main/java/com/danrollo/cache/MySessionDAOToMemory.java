package com.danrollo.cache;

/**
 * In memory session storage (via SessionDAO api).
 * User: dan
 * Date: 8/16/12
 * Time: 12:12 PM
 */
public class MySessionDAOToMemory extends MySessionDAO {

    public MySessionDAOToMemory() {
        super(new StorageToMemory("MySessionDAOStorageToMemory"));
    }
}
