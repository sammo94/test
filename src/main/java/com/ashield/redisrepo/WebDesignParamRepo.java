package com.ashield.redisrepo;

import com.ashield.datapojo.WebDesignParam;

public interface WebDesignParamRepo {
	void saveToWebDesignparamRepo(String key, WebDesignParam value);
	WebDesignParam getValueFromWebDesignparamRepo(String key);
	void deleteValueFromWebDesignparamRepo(String key);
}
