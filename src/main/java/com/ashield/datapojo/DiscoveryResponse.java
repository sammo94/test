package com.ashield.datapojo;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DiscoveryResponse implements Serializable{
	private String ttl;
	private String client_id;
	private String client_secret;
	private String serving_operator;
	private String country;
	private String currency;
	private String authorizationURL;
	private String tokenURL;
	private String issuerURL;
	private String userinfoURL;
	private String cpID;
	private String cpTxnID;
	private String cprdu;
	private String cpSerId;
	private String startTime;
	private String channel;
	private String auth;
}

