package com.danrollo.cache;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;

import java.io.*;
import java.util.*;

/**
 * A really crude disk based map. Saves after every change. Loads before every read.
 * User: dan
 * Date: 8/14/12
 * Time: 4:11 PM
 */
public class MyCache implements Cache {

    private Hashtable<Object, Object> diskProps = new Hashtable<Object, Object>();
    private final File diskFile;

    public MyCache(final String name) {
        diskFile = new File(System.getProperty("java.io.tmpdir"), name);
    }


    private synchronized void store() {
        DiskObject.store(diskFile, diskProps);
    }

    private synchronized void load() {
        if (!diskFile.exists()) {
            DiskObject.store(diskFile, diskProps);
        }

        //noinspection unchecked
        diskProps = (Hashtable<Object, Object>) DiskObject.load(diskFile);
    }


    /**
     * Returns the Cached value stored under the specified {@code key} or
     * {@code null} if there is no Cache entry for that {@code key}.
     *
     * @param key the key that the value was previous added with
     * @return the cached object or {@code null} if there is no entry for the specified {@code key}
     * @throws org.apache.shiro.cache.CacheException
     *          if there is a problem accessing the underlying cache system
     */
    @Override
    public Object get(Object key) throws CacheException {
        load();
        return diskProps.get(key);
    }

    /**
     * Adds a Cache entry.
     *
     * @param key   the key used to identify the object being stored.
     * @param value the value to be stored in the cache.
     * @return the previous value associated with the given {@code key} or {@code null} if there was previous value
     * @throws org.apache.shiro.cache.CacheException
     *          if there is a problem accessing the underlying cache system
     */
    @Override
    public Object put(Object key, Object value) throws CacheException {
        try {
            return diskProps.put(key, value);
        } finally {
            store();
        }
    }

    /**
     * Remove the cache entry corresponding to the specified key.
     *
     * @param key the key of the entry to be removed.
     * @return the previous value associated with the given {@code key} or {@code null} if there was previous value
     * @throws org.apache.shiro.cache.CacheException
     *          if there is a problem accessing the underlying cache system
     */
    @Override
    public Object remove(Object key) throws CacheException {
        try {
            return diskProps.remove(key);
        } finally {
            store();
        }
    }

    /**
     * Clear all entries from the cache.
     *
     * @throws org.apache.shiro.cache.CacheException
     *          if there is a problem accessing the underlying cache system
     */
    @Override
    public void clear() throws CacheException {
        try {
            diskProps.clear();
        } finally {
            store();
        }
    }

    /**
     * Returns the number of entries in the cache.
     *
     * @return the number of entries in the cache.
     */
    @Override
    public int size() {
        load();
        return diskProps.size();
    }

    /**
     * Returns a view of all the keys for entries contained in this cache.
     *
     * @return a view of all the keys for entries contained in this cache.
     */
    @Override
    public Set keys() {
        load();
        return diskProps.keySet();
    }

    /**
     * Returns a view of all of the values contained in this cache.
     *
     * @return a view of all of the values contained in this cache.
     */
    @Override
    public Collection values() {
        load();
        return diskProps.values();
    }
}
