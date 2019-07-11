package org.pentaho.hadoop.shim.common;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import org.apache.hadoop.security.UserGroupInformation;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * kerberos auth
 * 
 * @author yangchao
 *
 */
public class DataMaskingHadoopProxyUtilsParent {
	public static final String PRINCIPAL="principal";
	public static final String KEYTAB="keytab";
	public static final String CONF="conf";
	
	
	private static final Map<String, String> LOGIN_CONFIG_OPTS_KERBEROS_KEYTAB = createLoginConfigOptsKerberosKeytabMap();
	
	
	/**
	 * 获取subject
	 * 
	 * @param user
	 * @param keytab
	 * @param confStr
	 * @return
	 * @throws LoginException
	 * @throws IOException
	 */
	public static void getloginSubject(Map<String,String> config) throws Exception {
		if(config!=null&&config.containsKey(PRINCIPAL)&&config.containsKey(KEYTAB)&&config.containsKey(CONF)) {
			 getloginSubject(config.get(PRINCIPAL),config.get(KEYTAB),config.get(CONF));
		}else {
			throw new Exception("config error");
		}
		
	}
	
	
	
	/**
	 * 获取subject
	 * 
	 * @param user
	 * @param keytab
	 * @param confStr
	 * @return
	 * @throws LoginException
	 * @throws IOException
	 */
	public static  void getloginSubject(String user, String keytab, String confStr) throws Exception {
		System.setProperty("java.security.krb5.conf", confStr);
		UserGroupInformation loginUserFromKeytabAndReturnUGI = UserGroupInformation
				.loginUserFromKeytabAndReturnUGI(user, keytab);

	}

	/**
	 * 登陆subject
	 * 
	 * @param principal
	 * @param keytab
	 * @return
	 * @throws LoginException
	 */
	private static LoginContext getLoginContextFromKeytab(String principal, String keytab) throws LoginException {
		Map<String, String> keytabConfig = new HashMap<String, String>(LOGIN_CONFIG_OPTS_KERBEROS_KEYTAB);
		keytabConfig.put("keyTab", keytab);
		keytabConfig.put("principal", principal);
		@SuppressWarnings("restriction")
		AppConfigurationEntry config = new AppConfigurationEntry(
				com.sun.security.auth.module.Krb5LoginModule.class.getName(), LoginModuleControlFlag.REQUIRED,
				keytabConfig);
		AppConfigurationEntry[] configEntries = new AppConfigurationEntry[] { config };
		Subject subject = new Subject();
		return new LoginContext("dm-app-" + principal, subject, null, new DataMaskingLoginConfiguration(configEntries));
	}

	/**
	 * 配置config
	 * 
	 * @return
	 */
	private static Map<String, String> createLoginConfigOptsKerberosKeytabMap() {
		Map<String, String> result = new ConcurrentHashMap<String, String>();
		if (Boolean.parseBoolean(System.getenv("PENTAHO_JAAS_DEBUG"))) {
			result.put("debug", Boolean.TRUE.toString());
		}
		result.put("doNotPrompt", Boolean.TRUE.toString());
		result.put("useKeyTab", Boolean.TRUE.toString());
		result.put("storeKey", Boolean.TRUE.toString());
		result.put("refreshKrb5Config", Boolean.TRUE.toString());
		return Collections.unmodifiableMap(result);
	}

	/**
	 * 脱敏临时配置
	 * 
	 * @author yangchao
	 *
	 */
	public static class DataMaskingLoginConfiguration extends javax.security.auth.login.Configuration {
		private AppConfigurationEntry[] entries;

		public DataMaskingLoginConfiguration(AppConfigurationEntry[] entries) {
			if (entries == null) {
				throw new NullPointerException("AppConfigurationEntry[] is required");
			}
			this.entries = entries;
		}

		@Override
		public AppConfigurationEntry[] getAppConfigurationEntry(String ignored) {
			return entries;
		}
	}


	
}
