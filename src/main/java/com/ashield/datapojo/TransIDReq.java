package com.ashield.datapojo;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TransIDReq {
	private String df;
	private String tsp;
	private String mid;
	private String merTxnId;
	private String regnum;
	private String purpose;
	private String opn1;
	private String opn2;
	private int simcnt;
	private String ntype;
	private String status;
}
