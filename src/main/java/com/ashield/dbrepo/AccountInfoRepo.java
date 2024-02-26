package com.ashield.dbrepo;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.ashield.datapojo.AccountInfoEntity;

public interface AccountInfoRepo extends MongoRepository<AccountInfoEntity, String> {
	public AccountInfoEntity findByCustomerId(String mid);
}
