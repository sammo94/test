package com.ashield.logThread;

import org.springframework.beans.factory.annotation.Value;

import com.ashield.utils.Constants;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ASBotAnalyzeTimer extends Thread implements Constants {

	@Value("${botresp.timeout}")
	int BOTRESP_TIMEOUT;

	private String aTxnId;
	private String resp = null;
	private boolean abt = false;

	public ASBotAnalyzeTimer(String acpTxnID) {
		setATxnId(acpTxnID);
	}

	@Override
	public void run() {
		try {
			Thread.sleep(BOTRESP_TIMEOUT);
			resp = DEFAULT_RESP;
			abt = true;
			LoggingThread lt = new LoggingThread("[" + getATxnId() + "] " + "Default BotRespVal : " + resp);
			lt.start();
			Thread.sleep(10);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		super.run();
	}

}
