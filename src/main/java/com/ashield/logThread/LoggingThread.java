package com.ashield.logThread;

import com.ashield.logging.Logging;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class LoggingThread {

	private String info;

	public LoggingThread(String log) {
		setInfo(log);
	}

//	@Override
//	public synchronized void run() {
//		Logging.getLogger().info(getInfo());
//		super.run();
//	}

	public LoggingThread() {
		// TODO Auto-generated constructor stub
	}

	public synchronized void start() {
		Logging.getLogger().info(getInfo());
	}

}
