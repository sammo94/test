package com.ashield.datapojo;

import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString

@Document(collection="optvenver")
public class OptVebdorEntity {

	private String opt;
	private String vertype;
	private String vendor;
	private String status;
}
