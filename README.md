Log4Shell Hotfix Side Effect Test Case
======================================

I wanted to know if any `ClassNotFoundException` or similar unexpected
exception is raised when one applies the CVE-2021-44228 aka Log4Shell
hotfix as recommended [here](https://logging.apache.org/log4j/2.x/security.html#Fixed_in_Log4j_2.16.0).

Result: It looks like no exception is bubbling up.

To test this execute the following commands:
```
./gradlew clean installDist
env JAVA_OPTS=-Xmx64M ./build/install/log4shell-hotfix-side-effect/bin/log4shell-hotfix-side-effect
```

It will log two messages and there should be no exceptions.

If the log4j jar file is not patched properly there should be a measurable
delay between the messages (or you might even get an RCE, YMMV).
