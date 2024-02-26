package com.ashield.datapojo;

import java.sql.Timestamp;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@ToString
public class GetTxnIdPojo {
private Timestamp reqTS;
private String apiName;
private String aShieldTxnId;
private String merTxnId;
private String sdkVersion;
private String sdkType;
private String deviceTimestamp;
private String simCount;
private String selectedSim;
private String df;
private String IP;
private String bua;
private String nType;
private String mid;
private String purpose;
private String regnum;
private String flowType;
private String longCode;
private String opn1;
private String opn2;
private String status;
private String causeOfReRegTrigger;
private long processingTime;
private String mobileDataStatus;
private String transactionType;
private String regNumMatch;
private String environment;
private String circle;
}