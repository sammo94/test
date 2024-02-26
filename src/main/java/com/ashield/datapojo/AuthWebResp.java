package com.ashield.datapojo;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthWebResp implements Serializable{
	
	private static final long serialVersionUID = 1L;
	String token;
	String status;
	String txnID;
	String msisdn;
}
