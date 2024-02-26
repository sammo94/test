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

@Document(collection="prisecdf")
public class PriSecDFEntity {
	
	private String mid;
		
	
	private String pmdn;
	@Id
    private String devicefin;
	private String smdn;
	
}
