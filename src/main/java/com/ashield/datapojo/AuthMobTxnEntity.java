package com.ashield.datapojo;

import java.util.Date;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString

@Document(collection = "ashieldmobtxn")
public class AuthMobTxnEntity {

	private String mid;

	private String msisdn;
	@Id
	private String txnid;
	private String encTxnId;
	private boolean retrived;
	private String merTxnId;
	private Date createdAt;
	private Date updatedAt;
	private String status;
	// Req body information which is received in getTxnID
	private String req;
	// Device fingerprint coming in request
	private String df;
	private int smshlc;
	private String smsopr;

}
