package com.ashield.datapojo;

import java.util.Date;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class RegTxnRec {
	private String txnId;
	private String smsc;
	private String merTxnId;
	// Req body information which is received in getTxnID
	private String req;
	private String smsopr;
	private String status;
	private int expired;
	private int completed;
	private int success;
	private int total;
	private long smsTat;
	private String opn1;
	private String opn2;
	private int simcnt;
	private String ntype;
	private Date updatedAt;

}
