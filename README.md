shiro-test-dan
==============

Simple Test project(s) using Shiro


The branches contain various experiments:

    * minimalSSOWithCache - Contains only a custom SessionDAO implementation (MySesssionDAOToDisk).
                            Shiro is configured to use Ehcache for caching.

    * skunkworks - Contains attempts to store various objects in the Shiro session.

    * master - Contains custom Cache and CacheManager implementations in addition to SessionDAO implementations that can
            store to disk or in memory.


Setup

* To deploy to a local running tomcat 6 instance, make the following changes:

** Add a server block to .m2/settings.xml:

            <servers>
            ...
                <server>
                    <id>mylocalserver</id>
                    <username>tomcat</username>
                    <password>tomcat</password>
                </server>

** Add user/perms in tomcat/conf/tomcat-users.xml:

                      <role rolename="tomcat"/>
                      <user username="tomcat" password="tomcat" roles="tomcat,manager-gui,manager-script,manager-jmx,manager-status"/>

** Deploy to the local tomcat 6 instance using:

        mvn clean package tomcat6:redeploy

 The apps will be available at:

        http://localhost:8080/appone/
        http://localhost:8080/apptwo/

** You can launch a locally installed tomcat with remote debugging enabled on port 8000 using:

    apache-tomcat-6.0.35$ bin/catalina.sh jpda start

 Once deployed, you can login to each webapp with uid: admin, pwd: secret (see shiro.ini).
