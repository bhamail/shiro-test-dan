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

        * Add a server block to .m2/settings.xml:

                <servers>
                ...
                    <server>
                        <id>mylocalserver</id>
                        <username>tomcat</username>
                        <password>tomcat</password>
                    </server>

        * Add user/perms in tomcat/conf/tomcat-users.xml:

                          <role rolename="tomcat"/>
                          <user username="tomcat" password="tomcat" roles="tomcat,manager-gui,manager-script,manager-jmx,manager-status"/>

        * Deploy to the local tomcat 6 instance using:

            mvn clean package tomcat6:redeploy

          The apps will be available at:

            http://localhost:8080/appone/
            http://localhost:8080/apptwo/

    * You can launch a locally installed tomcat with remote debugging enabled on port 8000 using:

        apache-tomcat-6.0.35$ bin/catalina.sh jpda start


I'm also experimenting with publishing the maven site for this project on github gh-pages.
See: [wagon-scm -> Deploying your Maven site to GitHub's gh-pages](http://maven.apache.org/wagon/wagon-providers/wagon-scm/usage.html).
Doh! It looks like that approach is doomed: http://jira.codehaus.org/browse/WAGON-374.

Let's try this instead: http://maven.apache.org/plugins/maven-scm-publish-plugin/.
Well, that example, if run with the default user.home dir in shown in [Maven Multi Module Configuration](http://maven.apache.org/plugins/maven-scm-publish-plugin/examples/multi-module-configuration.html)
could end up deleting your entire home directory. Don't try that either.

OK, here's another approach: https://github.com/github/maven-plugins/.

The resulting site is available here: http://bhamail.github.com/shiro-test-dan/.