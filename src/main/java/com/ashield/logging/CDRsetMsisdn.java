package com.ashield.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ashield.datapojo.SetMsisdnPojo;

public class CDRsetMsisdn {

	private static final Logger log = LoggerFactory.getLogger(CDRsetMsisdn.class);
	private static volatile CDRsetMsisdn minstance = null;
	private static Object lock = new Object();

	public CDRsetMsisdn() {
		// TODO Auto-generated constructor stub
	}

	public static CDRsetMsisdn getCDRWriter() {
		if (minstance == null) {
			synchronized (lock) {
				if (minstance == null) {
					minstance = new CDRsetMsisdn();
				}
			}
		}
		return minstance;
	}

	public Logger getLogger() {
		return log;
	}

	public synchronized void logCDR(SetMsisdnPojo CdrInfo) {
		StringBuilder cdrData = new StringBuilder();
		cdrData.append(CdrInfo.getReqTS()).append(",").append(CdrInfo.getApiName()).append(",").append(CdrInfo.getAShieldTxnId()).append(",").append(CdrInfo.getMerTxnId()).append(",").append(CdrInfo.getSdkVersion()).append(",").append(CdrInfo.getSdkType()).append(",").append(CdrInfo.getDeviceTimestamp()).append(",").append(CdrInfo.getSimCount()).append(",").append(CdrInfo.getSelectedSim()).append(",").append(CdrInfo.getDf()).append(",").append(CdrInfo.getIP()).append(",").append(CdrInfo.getBua()).append(",").append(CdrInfo.getNType()).append(",")
	   	.append(CdrInfo.getMid()).append(",").append(CdrInfo.getPurpose()).append(",").append(CdrInfo.getRegnum()).append(",")		
	   	.append(CdrInfo.getFlowType()).append(",").append(CdrInfo.getLongCode()).append(",").append(CdrInfo.getOpn1()).append(",")
	   	.append(CdrInfo.getOpn2()).append(",").append(CdrInfo.getStatus()).append(",").append(CdrInfo.getCauseOfReRegTrigger()).append(",").append(CdrInfo.getProcessingTime()).append(",")
	   	.append(CdrInfo.getMobileDataStatus()).append(",").append(CdrInfo.getTransactionType()).append(",").append(CdrInfo.getRegNumMatch()).append(",").append(CdrInfo.getEnvironment()).append(",").append(CdrInfo.getCircle());
		log.debug(cdrData.toString());
	}

	public synchronized void dummylogCDRRotate() {
		log.debug("");
	}

}
