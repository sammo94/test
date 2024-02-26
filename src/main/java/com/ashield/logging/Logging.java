package com.ashield.logging;

import java.io.PrintWriter;
import java.io.StringWriter;

//import org.apache.log4j.Level;
//import org.apache.log4j.LogManager;
//import org.apache.log4j.PropertyConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Logging {

//	static {
//		PropertyConfigurator.configure(Logging.class.getResourceAsStream("/log4j.properties"));
//		LogManager.getRootLogger().setLevel(Level.INFO);
//	}

	private Logging() {

	}

	// private static final Logger log =
	// Logger.getLogger("com.ashield.logging.Logging");

	private static final Logger log = LoggerFactory.getLogger(Logging.class);

	public static Logger getLogger() {
		return log;
	}

	public synchronized static String getStackTrace(final Throwable throwable) {
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new PrintWriter(sw, true);
		throwable.printStackTrace(pw);
		return sw.getBuffer().toString();
	}

	public static void write(Object info) {
		log.info(info.toString());
	}

	public static void errorlog(Object errorMsg) {
		log.error(errorMsg.toString());
	}

}
