package com.danrollo.cache;

import org.apache.shiro.cache.AbstractCacheManager;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;

/**
 * Provides a crude disk based map cache instance.
 * User: dan
 * Date: 8/14/12
 * Time: 5:57 PM
 */
public class MyCacheManager extends AbstractCacheManager {

    /**
     * Creates a new {@code Cache} instance associated with the specified {@code name}.
     *
     * @param name the name of the cache to create
     * @return a new {@code Cache} instance associated with the specified {@code name}.
     * @throws org.apache.shiro.cache.CacheException
     *          if the {@code Cache} instance cannot be created.
     */
    @Override
    protected Cache createCache(String name) throws CacheException {
        return new MyCache(name);
    }
}
