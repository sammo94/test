package com.ashield.redisrepo;

public interface AuthTransactionIDRepo {
	void saveToAshiledAuthTranRepo(String key, String dfEncValue);

	void saveToAshieldAuthRepoWithTimeout(String key, String dfEncValue);

	String getValueFromAshiledAuthTranRepo(String key);

	void deleteValueFromAshiledAuthTranRepo(String key);

	void saveTxnID(String key, String txnID);

	String getTxnID(String key);

	void deleteTxnID(String key);

	void saveAuthTS(String key, String ts);

	String getAuthTS(String key);
}
