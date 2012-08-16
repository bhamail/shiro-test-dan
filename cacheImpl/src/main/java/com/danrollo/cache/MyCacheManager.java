package com.danrollo.cache;

import org.apache.shiro.cache.AbstractCacheManager;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;

/**
 * Provides a crude map cache instance.
 * User: dan
 * Date: 8/14/12
 * Time: 5:57 PM
 */
public class MyCacheManager extends AbstractCacheManager {

    private boolean isDisk;

    /** If true, store cache in disk file, otherwise store only in shared memory. Set via configuration, if at all. */
    public void setIsDisk(final boolean isDiskStorage) {
        isDisk = isDiskStorage;
    }

    /**
     * Creates a new {@code Cache} instance associated with the specified {@code name}.
     *
     * @param name the name of the cache to create
     * @return a new {@code Cache} instance associated with the specified {@code name}.
     * @throws org.apache.shiro.cache.CacheException
     *          if the {@code Cache} instance cannot be created.
     */
    @Override
    protected Cache createCache(final String name) throws CacheException {
        final Storage storage;
        if (isDisk) {
            storage = new StorageToDisk(name);
        } else {
            storage = new StorageToMemory(name);
        }
        return new MyCache(storage);
    }
}
