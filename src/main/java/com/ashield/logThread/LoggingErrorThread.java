package com.ashield.logThread;

import com.ashield.logging.Logging;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class LoggingErrorThread {

	private String errorMsg;

	public LoggingErrorThread(String errorMsg) {
		setErrorMsg(errorMsg);
	}

//	@Override
//	public synchronized void run() {
//		Logging.getLogger().error(getErrorMsg());
//		super.run();
//	}
	
	public synchronized void start() {
		Logging.getLogger().error(getErrorMsg());
	}

}
