package com.ashield.datapojo;

import java.util.Date;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class AuthTxnRec {
	private String txnId;
	private String merTxnId;
	private String s2;
	private String s3;
	private String passkey;
	private int simcnt;
	private String resp;
	private int success;
	private int failure;
	private long timestamp;
	private Date updatedAt;

}
