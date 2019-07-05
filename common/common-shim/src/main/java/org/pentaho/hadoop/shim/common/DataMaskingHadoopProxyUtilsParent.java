package org.pentaho.hadoop.shim.common;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * kerberos auth
 * 
 * @author yangchao
 *
 */
public class DataMaskingHadoopProxyUtilsParent {
	private static final String PRINCIPAL="principal";
	private static final String KEYTAB="keytab";
	private static final String CONF="conf";
	
	
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
	public static Subject getloginSubject(Map<String,String> config) throws Exception {
		if(config!=null&&config.containsKey(PRINCIPAL)&&config.containsKey(KEYTAB)&&config.containsKey(CONF)) {
			return getloginSubject(config.get(PRINCIPAL),config.get(KEYTAB),config.get(CONF));
		}
		throw new Exception("config error");
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
	public static Subject getloginSubject(String user, String keytab, String confStr) throws Exception {
		try {
			System.setProperty("java.security.krb5.conf", confStr);
			LoginContext loginContextFromKeytab = getLoginContextFromKeytab(user, keytab);
			loginContextFromKeytab.login();
			Subject subject = loginContextFromKeytab.getSubject();
			return subject;
		} catch (LoginException e) {
			throw e;
		}
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
		Map<String, String> result = new HashMap<String, String>();
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
