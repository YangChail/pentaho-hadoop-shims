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
import java.util.concurrent.atomic.AtomicLong;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hbase.client.Connection;
import org.apache.hadoop.hbase.client.ConnectionFactory;
import org.apache.hadoop.security.UserGroupInformation;

/**
 * kerberos auth
 * 
 * @author yangchao
 *
 */
public class DataMaskingHadoopProxyUtils extends DataMaskingHadoopProxyUtilsParent {
	private static AtomicLong lastDate=new AtomicLong(System.currentTimeMillis());
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
	public void hiveKerberosAuthLogin(Method method, Object[] args) throws Exception {
		if (method.getName().equals("connect")) {
			String connectUrl = (String) args[0];
			if (connectUrl.indexOf("principal=") > -1) {
				Map<String, String> config = getConfFromWeb(connectUrl);
				if (config != null) {
					String pricipal = config.get(PRINCIPAL);
					String userName = UserGroupInformation.getCurrentUser().getUserName();
					if(checkTime()&&userName.equalsIgnoreCase(pricipal)) {
						return;
					}
					Configuration conf = new Configuration();
					conf.set("hadoop.security.authentication", "kerberos");
					UserGroupInformation.setConfiguration(conf);
					// getloginSubject(config.get(PRINCIPAL), config.get(KEYTAB), config.get(CONF));
					System.setProperty("java.security.krb5.conf", config.get(CONF));
					UserGroupInformation.loginUserFromKeytab(config.get(PRINCIPAL), config.get(KEYTAB));
				}
			}
		}

	}
	
	private boolean checkTime() {
		long date=System.currentTimeMillis()-lastDate.get();
		if(date>(30*60*1000)) {
			lastDate.getAndSet(System.currentTimeMillis());
			logger.info("Re-login due to over 30 min last login");
			return false;
		}
		return true;
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
		String key = path.getAuthority();
		Map<String, String> config = getConfFromWeb(key);
		boolean flag = false;
		if ((config != null && config.containsKey(PRINCIPAL))) {
			flag = true;
		}
		if (flag) {
			try {
				String pricipal = config.get(PRINCIPAL);
				String user = UserGroupInformation.getCurrentUser().getUserName();
				if (checkTime()&&user.equalsIgnoreCase(pricipal)) {
					return;
				}
				UserGroupInformation.setConfiguration(conf);
				System.setProperty("java.security.krb5.conf", config.get(CONF));
				UserGroupInformation.loginUserFromKeytab(config.get(PRINCIPAL), config.get(KEYTAB));
				// logger.info(key + " kerberos login success");
			} catch (Exception e) {
				logger.error("kerberos login error", e);
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
		String key = path.getAuthority();
		Map<String, String> config = getConfFromWeb(key);
		boolean flag = false;
		if ((config != null && config.containsKey(PRINCIPAL))&&checkTime()) {
			flag = true;
		}
		if (flag) {
			try {
				String pricipal = config.get(PRINCIPAL);
				UserGroupInformation currentUser = UserGroupInformation.getCurrentUser();
				String username = currentUser.getUserName();
				if (checkTime()&&username.equals(pricipal)) {
					return currentUser;
				}
				UserGroupInformation.setConfiguration(conf);
				System.setProperty("java.security.krb5.conf", config.get(CONF));
				UserGroupInformation ugi = UserGroupInformation.loginUserFromKeytabAndReturnUGI(config.get(PRINCIPAL),
						config.get(KEYTAB));
				// logger.info(key + " kerberos login success");
				return ugi;
			} catch (Exception e) {
				logger.error("kerberos login error", e);
				return null;
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
			return getFileSystem(new URI(path), conf);
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

	public static Connection hbaseKerberosLogin(Configuration conf) throws IOException {
		String key = conf.get("hbase.zookeeper.quorum") + conf.get("hbase.zookeeper.property.clientPort");
		Map<String, String> confFromWeb = getConfFromWeb(key);
		Connection conn = null;
		// kerberos
		String kerberos = conf.get("hbase.security.authentication", "simpal");
		if (kerberos != null && "kerberos".equalsIgnoreCase(kerberos)) {
			System.setProperty("java.security.krb5.conf", confFromWeb.get(CONF));
			UserGroupInformation.setConfiguration(conf);
			UserGroupInformation loginUserFromKeytabAndReturnUGI = UserGroupInformation
					.loginUserFromKeytabAndReturnUGI(confFromWeb.get(PRINCIPAL), confFromWeb.get(KEYTAB));
			try {
				conn = loginUserFromKeytabAndReturnUGI.doAs(new PrivilegedExceptionAction<Connection>() {
					@Override
					public Connection run() throws Exception {
						return ConnectionFactory.createConnection(conf);
					}
				});
			} catch (InterruptedException e) {
				e.printStackTrace();
				throw new IOException("login hbase kerberos failture");
			}
		} else {
			conn = ConnectionFactory.createConnection(conf);
		}
		return conn;
	}

}