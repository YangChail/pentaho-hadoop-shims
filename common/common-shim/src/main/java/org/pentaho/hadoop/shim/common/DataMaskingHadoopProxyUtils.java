package org.pentaho.hadoop.shim.common;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivilegedExceptionAction;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.UserGroupInformation.AuthenticationMethod;

/**
 * kerberos auth
 * 
 * @author yangchao
 *
 */
public class DataMaskingHadoopProxyUtils extends DataMaskingHadoopProxyUtilsParent {
	public class loginCheckAndAddConfig {

	}

	protected static org.apache.log4j.Logger logger = org.apache.log4j.Logger
			.getLogger(DataMaskingHadoopProxyUtils.class);

	/**
	 * hive 的kerberos认证
	 * 
	 * @param method
	 * @param args
	 * @throws Exception
	 */
	public static synchronized void hiveKerberosAuthLogin(Method method, Object[] args) throws Exception {
		if (method.getName().equals("connect")) {
			String connectUrl = (String) args[0];
			if(connectUrl.indexOf("principal=")>-1) {
			Map<String, String> config = getConfFromWeb(connectUrl);
			if (config != null) {
				String pricipal = config.get(PRINCIPAL);
				if(UserGroupInformation.getCurrentUser().toString().equals(pricipal)) {
					return;
				}
				Configuration conf = new Configuration();
				conf.set("hadoop.security.authentication", "kerberos");
				UserGroupInformation.setConfiguration(conf);
				//getloginSubject(config.get(PRINCIPAL), config.get(KEYTAB), config.get(CONF));
				System.setProperty("java.security.krb5.conf", config.get(CONF));
				UserGroupInformation.loginUserFromKeytab(config.get(PRINCIPAL), config.get(KEYTAB));
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
	public void loginCheckAndAddConfig(String path, Configuration conf) {
		try {
			loginCheckAndAddConfig(new URI(path), conf);
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
	public void loginCheckAndAddConfig(URI path, Configuration conf) {
		addConfig(path, conf);
		UserGroupInformation.setConfiguration(conf);
		String string = conf.get(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHENTICATION);
		if (string != null && "KERBEROS".equalsIgnoreCase(string)) {
			String key = path.getAuthority();
			Map<String, String> config = getConfFromWeb(key);
			if (config != null) {
				try {
					String pricipal = config.get(PRINCIPAL);
					if(UserGroupInformation.getCurrentUser().toString().equals(pricipal)) {
						return;
					}
					System.setProperty("java.security.krb5.conf", config.get(CONF));
					UserGroupInformation.loginUserFromKeytab(config.get(PRINCIPAL), config.get(KEYTAB));
					FileSystem.get(path, conf);
					//logger.info(key + " kerberos login success");
				} catch (Exception e) {
					logger.error("kerberos login error", e);
				}
			}
		}

	}

	/**
	 * 通过文件地址从缓存拿出登陆
	 * 
	 * @param path
	 * @param conf
	 * @throws IOException 
	 */
	public UserGroupInformation loginCheckAndAddConfigReturnUGI(URI path, Configuration conf) throws IOException {
		addConfig(path, conf);
		String string = conf.get(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHENTICATION);
		if (string != null && "KERBEROS".equalsIgnoreCase(string)) {
			UserGroupInformation.setConfiguration(conf);
			String key = path.getAuthority();
			Map<String, String> config = getConfFromWeb(key);
			if (config != null) {
				try {
					String pricipal = config.get(PRINCIPAL);
					UserGroupInformation currentUser = UserGroupInformation.getCurrentUser();
					if(currentUser.toString().equals(pricipal)) {
						return currentUser;
					}
					System.setProperty("java.security.krb5.conf", config.get(CONF));
					UserGroupInformation ugi = UserGroupInformation
							.loginUserFromKeytabAndReturnUGI(config.get(PRINCIPAL), config.get(KEYTAB));
					//logger.info(key + " kerberos login success");
					return ugi;
				} catch (Exception e) {
					logger.error("kerberos login error", e);
					return null;
				}
			}
		}
		return UserGroupInformation.getCurrentUser();
	}

	/**
	 * 通过文件地址从缓存拿出登陆
	 * 
	 * @param path
	 * @param conf
	 * @throws InterruptedException
	 * @throws IOException
	 */
	public FileSystem getFileSystem(URI path, Configuration conf) throws IOException, InterruptedException {
		UserGroupInformation ugi = loginCheckAndAddConfigReturnUGI(path, conf);
		if (ugi != null) {
			FileSystem fs = ugi.doAs(new PrivilegedExceptionAction<FileSystem>() {
				public FileSystem run() throws Exception {
					return FileSystem.get(path, conf);
				}
			});

			return fs;
		}
		return FileSystem.get(path, conf);
	}
	
	
	/**
	 * 通过文件地址从缓存拿出登陆
	 * 
	 * @param path
	 * @param conf
	 * @throws InterruptedException
	 * @throws IOException
	 * @throws URISyntaxException 
	 */
	public FileSystem getFileSystem(String path, Configuration conf) throws IOException, InterruptedException {
		try {
			return getFileSystem(new URI(path),conf);
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static Map<String, String> getConfFromWeb(String key) {
		try {
			Class<?> classs = Class.forName("com.mchz.service.impl.source.DataMaskingHadoopUtils");
			if (classs != null) {
				Method saddMethod2 = classs.getMethod("getSUBJECT_MAP", null);
				if (saddMethod2 != null) {
					ConcurrentHashMap<String, Map<String, String>> subject_MAP = (ConcurrentHashMap<String, Map<String, String>>) saddMethod2
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

	public static List<String> getConfFileFromWeb(String key) {
		try {
			Class<?> classs = Class.forName("com.mchz.service.impl.source.DataMaskingHadoopUtils");
			if (classs != null) {
				Method saddMethod2 = classs.getMethod("getCONFIG_MAP", null);
				if (saddMethod2 != null) {
					ConcurrentHashMap<String, List<String>> subject_MAP = (ConcurrentHashMap<String, List<String>>) saddMethod2
							.invoke(null, null);
					if (subject_MAP != null && subject_MAP.size() > 0) {
						List<String> conf = subject_MAP.get(key);
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

	public static void addConfig(URI path, Configuration conf) {
		String authority = path.getAuthority();
		List<String> confFileFromWeb = getConfFileFromWeb(authority);
		if (confFileFromWeb != null && confFileFromWeb.size() > 0) {
			for (String str : confFileFromWeb) {
				if (conf.toString().indexOf(str) < 0) {
					Path uri = new Path(str);
					conf.addResource(uri);
				}
			}
		}
	}

}
