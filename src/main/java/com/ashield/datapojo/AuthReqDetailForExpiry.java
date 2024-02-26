package com.ashield.datapojo;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthReqDetailForExpiry {
	private String optxn;
	private String requestTime;
	private String token;
}
