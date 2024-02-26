package com.ashield.dbservice;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ashield.datapojo.AccountInfoEntity;
import com.ashield.datapojo.AuthMobDFEntity;
import com.ashield.datapojo.AuthMobTxnEntity;
import com.ashield.datapojo.AuthRegistryDoc;
import com.ashield.datapojo.AuthShareEntity;
import com.ashield.datapojo.ImgKeyEntity;
import com.ashield.datapojo.OptVebdorEntity;
import com.ashield.datapojo.PriSecDFEntity;
import com.ashield.datapojo.RegId;
import com.ashield.datapojo.SignKeyEntity;
import com.ashield.dbrepo.AccountInfoRepo;
import com.ashield.dbrepo.AuthMobRepo;
import com.ashield.dbrepo.AuthMobTxnRepo;
import com.ashield.dbrepo.AuthRegistryRepo;
import com.ashield.dbrepo.AuthShareRepo;
import com.ashield.dbrepo.ImgKeyRepo;
import com.ashield.dbrepo.OptVenRepo;
import com.ashield.dbrepo.PriSecRepo;
import com.ashield.dbrepo.SignKeyRepo;

@Service
public class DbService {

	@Autowired
	private AuthShareRepo mAuthShareRepo;

	@Autowired
	private SignKeyRepo mSignKeyRepo;

	@Autowired
	private ImgKeyRepo mImgKeyRepo;

	@Autowired
	private AuthMobRepo mAuthMobRepo;

	@Autowired
	private PriSecRepo mPriSecRepo;

	@Autowired
	private OptVenRepo mOptVendRepo;

	@Autowired
	private AccountInfoRepo mAccInfoRepo;

	@Autowired
	private AuthMobTxnRepo mAuthMobTxnRepo;

	@Autowired
	private AuthRegistryRepo mAuthRegRepo;
	
	public AccountInfoEntity getByCustomerID(String mid) {
		return mAccInfoRepo.findByCustomerId(mid);
	}

	public AuthShareEntity getByTxnID(String txnID) {
		return mAuthShareRepo.findByTxnid(txnID);
	}

	public AuthShareEntity getByNewtxnID(String txnID) {
		return mAuthShareRepo.findByNewtxnid(txnID);
	}

	public AuthShareEntity getByMertxnID(String txnID) {
		return mAuthShareRepo.findByMertxnid(txnID);
	}

	public List<AuthShareEntity> getByMsidn(String aMsisdn) {
		return mAuthShareRepo.findByMsisdn(aMsisdn);
	}

	public SignKeyEntity getByMid(String mid) {
		return mSignKeyRepo.findByCustomerId(mid);
	}

	public void saveSignKey(SignKeyEntity mSignData) {
		mSignKeyRepo.save(mSignData);
	}

	public ImgKeyEntity getImgByMid(String mid) {
		return mImgKeyRepo.findByCustomerId(mid);
	}

	public void saveImgKey(ImgKeyEntity mSignData) {
		mImgKeyRepo.save(mSignData);
	}

	public void saveShare(AuthShareEntity mShare) {
		mAuthShareRepo.save(mShare);
	}

	public AuthMobDFEntity getByMsisdn(String msisdn) {
		return mAuthMobRepo.findByMsisdn(msisdn);
	}

	public void saveDf(AuthMobDFEntity aDfData) {
		mAuthMobRepo.save(aDfData);
	}

	public List<PriSecDFEntity> getBypMdn(String pmdn) {
		return mPriSecRepo.findByPmdn(pmdn);
	}

	public void savePriSecDF(PriSecDFEntity aPriSecDfData) {
		mPriSecRepo.save(aPriSecDfData);
	}

	public OptVebdorEntity getByOperator(String oper, String status) {
		return mOptVendRepo.findByOptAndStatus(oper, status);
	}

	public void saveOptVend(OptVebdorEntity entity) {
		mOptVendRepo.save(entity);
	}

	public AuthMobTxnEntity getByTxnId(String txnid) {
		return mAuthMobTxnRepo.findByTxnid(txnid);
	}

	public void saveMob(AuthMobTxnEntity aDfData) {
		mAuthMobTxnRepo.save(aDfData);
	}

	public List<AccountInfoEntity> getAllMer() {
		return mAccInfoRepo.findAll();
	}

	public Optional<AuthRegistryDoc> findById(RegId id) {
		return mAuthRegRepo.findById(id);
	}

	public Optional<AuthRegistryDoc> findByTxnId(String txnId) {
		return mAuthRegRepo.findByTxnId(txnId);
	}
	
	public Optional<AuthRegistryDoc> findByRegTxnId(RegId id, String txnId) {
		return mAuthRegRepo.findByRegTxnId(id, txnId);
	}

	public AuthRegistryDoc saveAuthRegDoc(AuthRegistryDoc regDoc) {
		 return mAuthRegRepo.save(regDoc);
	}
}
