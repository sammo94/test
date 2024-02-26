package com.ashield.datapojo;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthReqDetail implements Serializable {
	String cpID;
	String cpTxnID;
	String cpRdu;
	String df;
	String devshare;
	String startTime;
	String newTxnID;
	String merTxnID;
	int simcount;
	String seckey;
	String channel;
	String clientURl;
	boolean cliOtp;
	boolean otpflow;
	boolean iPhone;
	boolean vpnflag;
	String vpnID;
	String vpnServerReq;
	boolean mulitdevice;
	boolean demography;
	String secTxnID;
	String primMsisdn;
	String secMsisdn;
	boolean authorize;
	boolean noconsent;
	boolean takeprime;
	boolean yesclick;
	boolean authtimeout;
	String diUrl;
	String bua;
	String mip;
	String devOsName;
	String browserName;
	String deviceModel;
	String isMobileNetwork;
	String netProvider;
	String opnName;
	String telco;
	String shareurl;
	String verType;
	String nitime;
	String smsurl;
	boolean isEmail;
	String senotp;
	String location;
	
	long retime;
	String tempStatus;
	String regnum;
	String reg_num_status;
}
