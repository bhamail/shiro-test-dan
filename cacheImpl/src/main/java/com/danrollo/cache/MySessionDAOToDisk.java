package com.danrollo.cache;

/**
 * On disk session storage (via SessionDAO api).
 * User: dan
 * Date: 8/16/12
 * Time: 12:14 PM
 */
public class MySessionDAOToDisk extends MySessionDAO {

    public MySessionDAOToDisk() {
        super(new StorageToDisk("MySessionDAOStorageToDisk"));
    }
}
