package com.ashield.dbrepo;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.AuthShareEntity;

@Repository
public interface AuthShareRepo extends MongoRepository<AuthShareEntity, String> {
	public AuthShareEntity findByNewtxnid(String txnId);

	public List<AuthShareEntity> findByMsisdn(String aMsisdn);
	public AuthShareEntity findByMertxnid(String txnID);
	public AuthShareEntity findByTxnid(String txnID);
}
