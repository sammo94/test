package com.ashield.dbrepo;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.AuthMobDFEntity;

@Repository
public interface AuthMobRepo extends MongoRepository<AuthMobDFEntity, String> {
	public AuthMobDFEntity findByMsisdn(String msisdn);
}
