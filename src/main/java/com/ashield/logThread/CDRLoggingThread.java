package com.ashield.logThread;

import com.ashield.datapojo.AuthReqDetail;
import com.ashield.logging.CDRLogging;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class CDRLoggingThread {

	private AuthReqDetail aDetail;
	private String aMsisdn;
	private String statuscode;
	private String imgResp;

	public CDRLoggingThread(AuthReqDetail aDetail, String aMsisdn, String statuscode, String imgResp) {
		setADetail(aDetail);
		setAMsisdn(aMsisdn);
		setStatuscode(statuscode);
		setImgResp(imgResp);
	}
//
//	@Override
//	public synchronized void run() {
//		CDRLogging.getCDRWriter().logCDR(getADetail(), getAMsisdn(), getStatuscode(), getImgResp());
//		super.run();
//	}
	public synchronized void start() {
		CDRLogging.getCDRWriter().logCDR(getADetail(), getAMsisdn(), getStatuscode(), getImgResp());
	}

}
