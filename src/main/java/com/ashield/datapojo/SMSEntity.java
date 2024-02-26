package com.ashield.datapojo;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
public class SMSEntity {

	private String longcode;
	private String operator;
	private String percentage;

	@Override
	public String toString() {
		return "{longcode=" + longcode + ", operator=" + operator + ", percentage=" + percentage + "}";
	}

}
