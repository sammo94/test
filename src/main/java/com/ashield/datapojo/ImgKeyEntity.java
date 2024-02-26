package com.ashield.datapojo;

import org.bson.types.Binary;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString

@Document(collection = "imgsign")
public class ImgKeyEntity {

	@Id
	private String customerId;

	// private Binary imgstr;
	private String imgstr;
	private String gifstr;

}
