package org.pentaho.hadoop.shim.common;

import java.lang.reflect.Method;

import org.apache.hadoop.conf.Configuration;

/**
 * kerberos auth
 * 
 * @author yangchao
 *
 */
public class KerberosAuth {
	private static String principal;
	private static String confPath="";
	private static String keytabPath;
	private static boolean useKerberos;
	public static  org.apache.hadoop.conf.Configuration configuration;

	public static void hadoopKerberosAuthLogin(org.pentaho.hadoop.shim.api.Configuration conf) {
		useKerberos = conf.get("dm.hadoop.usekerberos").equals("true") ? true : false;
		if (useKerberos) {
			principal = conf.get("dm.hadoop.principal");
			keytabPath = conf.get("dm.hadoop.keytabPath");
			confPath = conf.get("dm.hadoop.confPath");
			if(confPath!=null&&confPath.length()>0) {
				System.setProperty("java.security.krb5.conf", confPath);
			}
			try {
				org.apache.hadoop.security.UserGroupInformation.setConfiguration(org.pentaho.hadoop.shim.common.ShimUtils.asConfiguration(conf));
				org.apache.hadoop.security.UserGroupInformation.loginUserFromKeytab(principal, keytabPath);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	

	public static void hiveKerberosAuthLogin(Method method, Object[] args) {
		if(method.getName().equals("connect")&&method.getParameterTypes().length==2) {
			String principal="";
			String keytabPath="";
			String connectUrl = (String) args[0];
			if(connectUrl.startsWith( "jdbc:hive" )) {
				String[] split = connectUrl.split(";");
				for(String parm:split) {
					if(parm.startsWith("keytab=")) {
						keytabPath=spit(parm);
					}else if(parm.startsWith("principal=")) {
						principal=spit(parm);
					}
				}
			}
			if(!principal.equals("")&&!keytabPath.equals("")) {
				try {
					Configuration conf = new Configuration();
					conf.set("hadoop.security.authentication", "kerberos");
					org.apache.hadoop.security.UserGroupInformation.setConfiguration(conf);
					org.apache.hadoop.security.UserGroupInformation.loginUserFromKeytab(principal, keytabPath);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			
			
		}
			
	}
	
	public static String spit(String parm) {
		String[] split2 = parm.split("=");
		String str=split2[1];
		if(str.startsWith("'")&&str.endsWith("'")&&str.length()>3) {
			return str.substring(1, str.length()-1);
		}else {
			return split2[1];
		}
	}
	
	
	
}
