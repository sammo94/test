package com.ashield.datapojo;


import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class RegId {
	// Finger print from client
	private String df;
	// ID assigned for enterprise
	private String mid;
	
	public RegId(String df, String mid) {
		this.df = df;
		this.mid = mid;
	}

}
