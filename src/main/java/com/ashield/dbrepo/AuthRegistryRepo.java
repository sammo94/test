package com.ashield.dbrepo;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.AuthRegistryDoc;
import com.ashield.datapojo.RegId;


@Repository
public interface AuthRegistryRepo extends MongoRepository<AuthRegistryDoc, RegId>{
	public Optional<AuthRegistryDoc> findById(RegId id);

	 @Query("{'txnId': ?0}") 
	 public Optional<AuthRegistryDoc> findByTxnId(String txnId);
	 
	 @Query("{'_id': ?0, 'txnId' : ?1}") 
	 public Optional<AuthRegistryDoc> findByRegTxnId(RegId id, String txnId);
	
}
