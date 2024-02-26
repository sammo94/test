package com.ashield.dbrepo;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.ashield.datapojo.SignKeyEntity;

public interface SignKeyRepo extends MongoRepository<SignKeyEntity, String> {
	public SignKeyEntity findByCustomerId(String mid);
}
