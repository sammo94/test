package com.ashield.datapojo;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@ToString
public class SetLockCount {
	private String reqTS;
    private String aTxnID;
    private String purpose;
    private String mid;
    private long processingTime;
    private String apiName;
    private String deviceTimestamp;

}
