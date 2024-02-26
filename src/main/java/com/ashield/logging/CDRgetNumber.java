package com.ashield.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ashield.datapojo.GetNumberPojo;

public class CDRgetNumber {

	// included

	private static final Logger log = LoggerFactory.getLogger(CDRgetNumber.class);
	private static volatile CDRgetNumber minstance = null;
	private static Object lock = new Object();

	// included

	public CDRgetNumber() {
		// TODO Auto-generated constructor stub
	}

	// included

	public static CDRgetNumber getCDRWriter() {
		if (minstance == null) {
			synchronized (lock) {
				if (minstance == null) {
					minstance = new CDRgetNumber();
				}
			}
		}

		return minstance;
	}

//included 

	public Logger getLogger() {
		return log;
	}

	// included

	public synchronized void logCDR(GetNumberPojo CdrInfo) {
		StringBuilder cdrData = new StringBuilder();
		cdrData.append(CdrInfo.getReqTS()).append(",").append(CdrInfo.getApiName()).append(",").append(CdrInfo.getAShieldTxnId()).append(",")
	       .append(CdrInfo.getMerTxnId()).append(",").append(CdrInfo.getSdkVersion()).append(",").append(CdrInfo.getSdkType()).append(",")
	       .append(CdrInfo.getDeviceTimestamp()).append(",").append(CdrInfo.getSimCount()).append(",").append(CdrInfo.getSelectedSim()).append(",").append(CdrInfo.getDf()).append(",")	
	       .append(CdrInfo.getIP()).append(",").append(CdrInfo.getBua()).append(",").append(CdrInfo.getNType()).append(",")
	       .append(CdrInfo.getMid()).append(",").append(CdrInfo.getPurpose()).append(",").append(CdrInfo.getRegnum()).append(",").append(CdrInfo.getFlowType()).append(",")
	       .append(CdrInfo.getLongCode()).append(",").append(CdrInfo.getOpn1()).append(",").append(CdrInfo.getOpn2()).append(",").append(CdrInfo.getStatus()).append(",").append(CdrInfo.getCauseOfReRegTrigger()).append(",")
	       .append(CdrInfo.getProcessingTime()).append(",").append(CdrInfo.getMobileDataStatus()).append(",").append(CdrInfo.getTransactionType()).append(",").append(CdrInfo.getRegNumMatch()).append(",").append(CdrInfo.getEnvironment()).append(",").append(CdrInfo.getCircle());	
		log.debug(cdrData.toString());
	}

	public synchronized void dummylogCDRRotate() {
		log.debug("");
	}

}
