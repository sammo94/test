package com.ashield.dbrepo;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.ashield.datapojo.OptVebdorEntity;
import java.lang.String;
import java.util.List;

@Repository
public interface OptVenRepo extends MongoRepository<OptVebdorEntity, String> {
	public List<OptVebdorEntity> findByOpt(String Opt);

	public OptVebdorEntity findByOptAndStatus(String opt, String status);
}
