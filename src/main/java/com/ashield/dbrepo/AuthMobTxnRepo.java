package com.ashield.dbrepo;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.AuthMobTxnEntity;



@Repository
public interface AuthMobTxnRepo extends MongoRepository<AuthMobTxnEntity, String>{
	public AuthMobTxnEntity findByTxnid(String txnid);
}
