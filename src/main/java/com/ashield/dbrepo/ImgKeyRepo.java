package com.ashield.dbrepo;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.ashield.datapojo.ImgKeyEntity;

public interface ImgKeyRepo extends MongoRepository<ImgKeyEntity, String> {
	public ImgKeyEntity findByCustomerId(String mid);
}
