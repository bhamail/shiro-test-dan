package com.danrollo.cacheImpl;

import net.sf.ehcache.CacheManager;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.ehcache.EhCacheManager;

/**
 * Created with IntelliJ IDEA.
 * User: dan
 * Date: 8/14/12
 * Time: 12:22 PM
 * To change this template use File | Settings | File Templates.
 */
public class MyCacheImpl extends EhCacheManager {

    @Override
    public CacheManager getCacheManager()
    {
        return CacheManager.getInstance();
    }
}
