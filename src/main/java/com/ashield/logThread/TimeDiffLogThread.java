package com.ashield.logThread;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class TimeDiffLogThread {

	private long currentTimeMillis;
	private long currentTimeMillis2;
	private String key;
	private String rwinfo;
	private String txnID;

	public TimeDiffLogThread(String val) {
		setKey(val);
	}

	public TimeDiffLogThread(String val, String rwinfo) {
		setKey(val);
		setRwinfo(rwinfo);
	}

	public String start() {

		String resp = "";
		try {
			long diff = currentTimeMillis2 - currentTimeMillis;
			if (diff < 0)
				diff = -1 * diff;
			String diffresp = diff(diff);

			switch (getKey()) {

			case "getTxnIDdb":
				resp = ("getTxnID-DB " + getRwinfo() + " duration time: " + diffresp);
				break;

			case "AsAuthappbot":
				resp = ("AsAuth-Appbot response duration time: " + diffresp);
				break;

			case "AuthShareEntity":
				resp = ("AsAuth-AuthShareEntity-DB " + getRwinfo() + " duration time: " + diffresp);
				break;

			case "AuthMobDFEntity":
				resp = ("AsAuth-AuthMobDFEntity-DB " + getRwinfo() + " duration time: " + diffresp);
				break;

			case "AuthMobTxnEntity":
				resp = ("AsAuth-AuthMobTxnEntity-DB " + getRwinfo() + " duration time: " + diffresp);
				break;

			case "PriSecDFEntity":
				resp = ("AsAuth-PriSecDFEntity-DB " + getRwinfo() + " duration time: " + diffresp);
				break;

			case "ImgKeyEntity":
				resp = ("AsAuth-ImgKeyEntity-DB " + getRwinfo() + " duration time: " + diffresp);
				break;

			case "getTxnIDapi":
				resp = ("GetTxnID-API response duration time: " + diffresp);
				break;

			case "AsAuthapi":
				resp = ("AsAuth-API response duration time: " + diffresp);
				break;

			case "setmsisdnapi":
				resp = ("setmsisdn-API response duration time: " + diffresp);
				break;

			case "chkmsisdn":
				resp = ("chkmsisdn-API response duration time: " + diffresp);
				break;

			case "getsecure-img":
				resp = ("getsecure-img-API response duration time: " + diffresp);
				break;

			case "verify-mob":
				resp = ("verify-mob-API response duration time: " + diffresp);
				break;

			case "tokenReqInfo":
				resp = ("tokenReqInfo-API response duration time: " + diffresp);
				break;

			case "tokenReqZom":
				resp = ("tokenReqZom-API response duration time: " + diffresp);
				break;

			case "tokenReq":
				resp = ("tokenReq-API response duration time: " + diffresp);
				break;

			case "validate-img":
				resp = ("validate-img-API response duration time: " + diffresp);
				break;

			case "validate-img-load":

				resp = ("validate-img-load-API response duration time: " + diffresp);
				break;

			case "dispdemog":
				resp = ("dispdemog-API response duration time: " + diffresp);
				break;

			case "sendotp":
				resp = ("sendotp-API response duration time: " + diffresp);
				break;

			case "sendverify":
				resp = ("sendverify-API response duration time: " + diffresp);
				break;

			case "inbipcallback":
				resp = ("inbipcallback-API response duration time: " + diffresp);
				break;

			case "insertvenopr":
				resp = ("insertvenopr-API response duration time: " + diffresp);
				break;

			case "getNumber":
				resp = ("getNumber-API response duration time: " + diffresp);
				break;

			case "setLockCount":
				resp = ("setLockCount-API response duration time: " + diffresp);
				break;

			case "cputime":
				resp = ("Effective CPU processing time: " + diffresp);
				break;

			case "UPDATE-MERCHANT-CONFIG":
				resp = ("UPDATE-MERCHANT-CONFIG api response duration time: " + diffresp);
				break;
			default:
				resp = getKey() + " response duration time:" + diffresp;
			}
		} catch (Exception e) {
			resp = e.toString();
		}
		return resp;

	}

	private static String diff(long diff) {
		String resp = "";
		try {
			// in milliseconds
			long diffMiliSeconds = diff % 1000;
			long diffSeconds = diff / 1000 % 60;
			long diffMinutes = diff / (60 * 1000) % 60;
			long diffHours = diff / (60 * 60 * 1000) % 24;
			long diffDays = diff / (24 * 60 * 60 * 1000);

			if (diffDays != 0)
				resp = resp + (diffDays + " days, ");

			if (diffHours != 0)
				resp = resp + (diffHours + " hours, ");

			if (diffMinutes != 0)
				System.out.print(diffMinutes + " minutes, ");

			if (diffSeconds != 0)
				resp = resp + (diffSeconds + " seconds, ");

			if (diffMiliSeconds != 0)
				resp = resp + (diffMiliSeconds + " milliseconds.");

		} catch (Exception e) {
			e.printStackTrace();
		}

		if (resp.isEmpty())
			resp = "0";

		return resp;
	}

}
