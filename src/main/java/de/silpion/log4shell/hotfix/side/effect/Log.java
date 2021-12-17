package de.silpion.log4shell.hotfix.side.effect;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.Logger;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Log {
    private final Method method;
    private final String format;
    private final Object[] gadget;

    private Log(
        final String method,
        final String placeholder,
        final String gadget
    ) {
        try {
            this.method = Logger.class.getMethod(
                method,
                Level.class,
                String.class,
                Object[].class
            );
            this.format = "Trigger: " + placeholder;
            this.gadget = new Object[]{gadget};
        }
        catch (NoSuchMethodException e) {
            throw new RuntimeException("Unexpected reflection exception: " + e, e);
        }
    }

    public static Log log(
        final String gadget
    ) {
        return new Log(
            "log",
            "{}",
            gadget
        );
    }

    public static Log printf(
        final String gadget
    ) {
        return new Log(
            "printf",
            "%s",
            gadget
        );
    }

    public void invoke(
        Logger logger
    ) {
        try {
            method.invoke(
                logger,
                Level.INFO,
                format,
                gadget
            );
        }
        catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException("Unexpected reflection exception: " + e, e);
        }
    }
}
