package com.ashield.logging;

//import org.apache.log4j.Level;
//import org.apache.log4j.LogManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import org.apache.log4j.PropertyConfigurator;

public class ErrorLogging {

	private ErrorLogging() {
		// restrict instantiation
	}

//	static {
//		PropertyConfigurator.configure(Logging.class.getResourceAsStream("/log4j.properties"));
//		LogManager.getRootLogger().setLevel(Level.INFO);
//	}

	private static final Logger errlog = LoggerFactory.getLogger(ErrorLogging.class);

	public static Logger getLogger() {
		return errlog;
	}

	public static void write(String info) {
		errlog.info(info);
	}
}
