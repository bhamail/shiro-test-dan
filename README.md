shiro-test-dan
==============

Simple Test project(s) using Shiro


The branches contain various experiments:

    * minimalSSOWithCache - Contains only a custom SessionDAO implementation (MySesssionDAOToDisk).
                            Shiro is configured to use Ehcache for caching.

    * skunkworks - Contains attempts to store various objects in the Shiro session.

    * master - Contains custom Cache and CacheManager implementations in addition to SessionDAO implementations that can
            store to disk or in memory.
