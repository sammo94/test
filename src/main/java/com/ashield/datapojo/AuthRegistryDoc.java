package com.ashield.datapojo;

import java.util.Date;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString

@Document(collection = "authregistry")
public class AuthRegistryDoc {
	public static final int REG_INITIATED = 1;
	public static final int SMS_RECEIVED = 2;
	public static final int REG_SUCCESS = 3;
	public static final int REG_FAILURE = 4;
	public static final int TELCO_INITIATED = 5;
	public static final int TELCO_FAILED = 6;
	public static final int TELCO_SUCCESS = 7;
	public static final int AUTH_INITIATED = 8;
	public static final int AUTH_SUCCESS = 9;
	public static final int AUTH_FAILURE = 10;

	public static final int FLOW_TELCO = 0;
	public static final int FLOW_MO = 1;

	public static final int API_GETTXNID = 1;
	public static final int API_ASAUTH = 2;
	public static final int API_SETMSISDN = 3;
	public static final int API_TOKENREQZOM = 4;

	@Id
	private RegId id;
	// This will give the last API which accessed this information
	private int api;
	// Based on other parameters will decide
	// The auth flow for this entry e.g. MO or TELCO
	private int authFlow;
	private String longCode;
	private String telcoUrl;
	// Incoming reg number in request
	private String regnum;
	// MSISDN identified by AShield
	private String msisdn;
	private String rdu;

	private int state;
	// Recent txnID
	private String txnId;
	// Recent merTxnId
	private String merTxnId;
	// This will be used for primary reg req
	private RegTxnRec regTxn;
	// This will be used for primary auth req
	private AuthTxnRec authTxn;
	// For FIDO one more txnRec will be used for both reg, auth
	// Operator name
	private String opn;
	private String ntype;
	private String purpose;
	// Created at when first request came
	private Date createdAt;
	// When re-reg/re-auth happens
	private Date updatedAt;
	// Last status code sent for the last api request
	private String statusCode;
	// telco flow registration verification type
	private String telcoVeriType;

	private boolean iphone;
}
