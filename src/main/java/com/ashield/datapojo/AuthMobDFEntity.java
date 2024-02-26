package com.ashield.datapojo;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString

@Document(collection = "ashieldmobdf")
public class AuthMobDFEntity {

	private String mid;

	@Id
	private String msisdn;
	private String devicefin;
	private String channel;

}
