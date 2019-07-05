package org.pentaho.hadoop.shim.common;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.Subject;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.UserGroupInformation.AuthenticationMethod;

/**
 * kerberos auth
 * 
 * @author yangchao
 *
 */
public class DataMaskingHadoopProxyUtils extends DataMaskingHadoopProxyUtilsParent {
	protected static org.apache.log4j.Logger logger = org.apache.log4j.Logger
			.getLogger(DataMaskingHadoopProxyUtils.class);
	private static ConcurrentHashMap<String, Configuration> CONFIGURATION_MAP = new ConcurrentHashMap<>();

	/**
	 * hive 的kerberos认证
	 * 
	 * @param method
	 * @param args
	 */
	public static void hiveKerberosAuthLogin(Method method, Object[] args) {
		if (method.getName().equals("connect") && method.getParameterTypes().length == 2) {
			String principal = "";
			String keytabPath = "";
			String connectUrl = (String) args[0];
			if (connectUrl.startsWith("jdbc:hive")) {
				String[] split = connectUrl.split(";");
				for (String parm : split) {
					if (parm.startsWith("keytab=")) {
						keytabPath = spit(parm);
					} else if (parm.startsWith("principal=")) {
						principal = spit(parm);
					}
				}
			}
			if (!principal.equals("") && !keytabPath.equals("")) {
				try {
					Configuration conf = new Configuration();
					conf.set("hadoop.security.authentication", "kerberos");
					org.apache.hadoop.security.UserGroupInformation.setConfiguration(conf);
					org.apache.hadoop.security.UserGroupInformation.loginUserFromKeytab(principal, keytabPath);
				} catch (Exception e) {
					logger.error(e);
				}
			}

		}

	}

	/**
	 * 通过文件地址从缓存拿出登陆
	 * 
	 * @param path
	 * @param conf
	 */
	public static void loginKerberos(String path, Configuration conf) {
		try {
			loginKerberos(new URI(path), conf);
		} catch (URISyntaxException e) {
			logger.error("kerberos login error", e);
		}
	}

	/**
	 * 通过文件地址从缓存拿出登陆
	 * 
	 * @param path
	 * @param conf
	 */
	public static void loginKerberos(URI path, Configuration conf) {
		if (SecurityUtil.getAuthenticationMethod(conf) == AuthenticationMethod.KERBEROS) {
			String key;
			key = path.getAuthority();
			Map<String, String> subject = getConfFromWeb(key);
			reflactDataMaskingSubject(path, conf, subject);
		}

	}

	public static void reflactDataMaskingSubject(URI path, Configuration conf,Map<String, String> subject) {
		try {
			if (subject == null) {
				logger.error("no subject in cash with " + path);
				return;
			}
			Subject getloginSubject = getloginSubject(subject);
			UserGroupInformation.setConfiguration(conf);
			UserGroupInformation.loginUserFromSubject(getloginSubject);
			logger.info("kerberos login success");
		} catch ( Exception e) {
			logger.error("kerberos login error", e);
		}
	}

	public static String spit(String parm) {
		String[] split2 = parm.split("=");
		String str = split2[1];
		if (str.startsWith("'") && str.endsWith("'") && str.length() > 3) {
			return str.substring(1, str.length() - 1);
		} else {
			return split2[1];
		}
	}

	public static 	Map<String, String>  getConfFromWeb(String key) {
		try {
			Class<?> classs = Class.forName("com.mchz.service.impl.source.DataMaskingHadoopUtils");
			if (classs != null) {
				Method saddMethod2 = classs.getMethod("getSUBJECT_MAP", null);
				if (saddMethod2 != null) {
					 ConcurrentHashMap<String, Map<String,String>> subject_MAP = ( ConcurrentHashMap<String, Map<String,String>>) saddMethod2
							.invoke(null, null);
					if (subject_MAP != null && subject_MAP.size() > 0) {
						Map<String, String> conf = subject_MAP.get(key);
						if (conf != null) {
							return conf;
						}
					}
				}
			}

		} catch (ClassNotFoundException | NoSuchMethodException | SecurityException | IllegalAccessException
				| IllegalArgumentException | InvocationTargetException e) {
			logger.error(e);
		}
		return null;
	}

	public static ConcurrentHashMap<String, Configuration> getCONFIGURATION_MAP() {
		return CONFIGURATION_MAP;
	}
}
