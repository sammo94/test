package com.ashield.dbrepo;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.PriSecDFEntity;
import java.lang.String;
import java.util.List;

@Repository
public interface PriSecRepo extends MongoRepository<PriSecDFEntity, String> {
	public List<PriSecDFEntity> findByPmdn(String pmdn);
}
