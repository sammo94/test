package com.ashield.logThread;

import com.ashield.logging.ErrorLogging;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ErrorLoggingThread {

	private String info;

	public ErrorLoggingThread(String info) {
		setInfo(info);
	}

//	@Override
//	public synchronized void run() {
//		ErrorLogging.getLogger().info(getInfo());
//		super.run();
//	}

	public ErrorLoggingThread() {
		// TODO Auto-generated constructor stub
	}

	public synchronized void start() {
		ErrorLogging.getLogger().info(getInfo());
	}
}
