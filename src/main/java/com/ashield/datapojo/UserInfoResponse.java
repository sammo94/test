package com.ashield.datapojo;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserInfoResponse implements Serializable{
	 private String sub;
	 private String device_msisdn;
}
