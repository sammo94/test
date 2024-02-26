package com.ashield.datapojo;

import lombok.Getter;

@Getter
public class Smsc {
	private String longCode;
	private String operator;
	private int percentage;

	public Smsc(String lc, String op, int per) {
		longCode = lc;
		operator = op;
		percentage = per;
	}
};