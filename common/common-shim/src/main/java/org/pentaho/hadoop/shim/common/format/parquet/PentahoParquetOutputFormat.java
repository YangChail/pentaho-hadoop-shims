/*******************************************************************************
 *
 * Pentaho Big Data
 *
 * Copyright (C) 2018 by Hitachi Vantara : http://www.pentaho.com
 *
 *******************************************************************************
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************************/
package org.pentaho.hadoop.shim.common.format.parquet;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileAlreadyExistsException;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.util.List;

import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.TaskAttemptID;
import org.apache.hadoop.mapreduce.TaskType;
import org.apache.hadoop.mapreduce.task.TaskAttemptContextImpl;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.log4j.Logger;

//#if shim_type=="HDP" || shim_type=="EMR" || shim_type=="HDI" || shim_name=="mapr60"
import org.apache.parquet.column.ParquetProperties;
import org.apache.parquet.hadoop.Footer;
import org.apache.parquet.hadoop.ParquetFileReader;
import org.apache.parquet.hadoop.ParquetOutputFormat;
import org.apache.parquet.hadoop.ParquetRecordWriter;
import org.apache.parquet.hadoop.metadata.CompressionCodecName;
//#endif
//#if shim_type=="CDH" || shim_type=="MAPR" && shim_name!="mapr60"
//$import parquet.column.ParquetProperties;
//$import parquet.hadoop.ParquetOutputFormat;
//$import parquet.hadoop.ParquetRecordWriter;
//$import parquet.hadoop.metadata.CompressionCodecName;
//#endif

import org.pentaho.di.core.RowMetaAndData;
import org.pentaho.hadoop.shim.api.format.IParquetOutputField;
import org.pentaho.hadoop.shim.api.format.IPentahoParquetOutputFormat;
import org.pentaho.hadoop.shim.common.ConfigurationProxy;
import org.pentaho.hadoop.shim.common.DataMaskingHadoopProxyUtils;
import org.pentaho.hadoop.shim.common.format.HadoopFormatBase;
import org.pentaho.hadoop.shim.common.format.S3NCredentialUtils;

/**
 * Created by Vasilina_Terehova on 8/3/2017.
 */
public class PentahoParquetOutputFormat extends HadoopFormatBase implements IPentahoParquetOutputFormat {

	private static final Logger logger = Logger.getLogger(PentahoParquetInputFormat.class);
	private static final String S3SCHEME = "s3";
	private static final String S3NSCHEME = "s3n";
	private static final String S3NROOTBUCKET = S3NSCHEME + "/";

	private Job job;
	private Path outputFile;
	private List<? extends IParquetOutputField> outputFields;

	public PentahoParquetOutputFormat() throws Exception {
		logger.info("We are initializing parquet output format");
		inClassloader(() -> {
			ConfigurationProxy conf = new ConfigurationProxy();
			job = Job.getInstance(conf);
			job.getConfiguration().set(ParquetOutputFormat.ENABLE_JOB_SUMMARY, "false");
			ParquetOutputFormat.setEnableDictionary(job, false);
		});
	}

	@Override
	public void setFields(List<? extends IParquetOutputField> fields) throws Exception {
		this.outputFields = fields;
	}

	@Override
	public void setOutputFile(String file, boolean override) throws Exception {
		inClassloader(() -> {
			S3NCredentialUtils.applyS3CredentialsToHadoopConfigurationIfNecessary(file, job.getConfiguration());
			outputFile = new Path(S3NCredentialUtils.scrubFilePathIfNecessary(file));
			lock.lock();
			DataMaskingHadoopProxyUtils dataMaskingHadoopProxyUtils = new DataMaskingHadoopProxyUtils();
			System.out.println("out---"+UserGroupInformation.getCurrentUser());
			UserGroupInformation ugi = dataMaskingHadoopProxyUtils.loginCheckAndAddConfigReturnUGI(outputFile.toUri(),
					job.getConfiguration());
			ugi.doAs(new PrivilegedAction<FileSystem>() {
				@Override
				public FileSystem run() {
					FileSystem fs = null;
					try {
						fs = FileSystem.get(outputFile.toUri(), job.getConfiguration());
						System.out.println("out---"+UserGroupInformation.getCurrentUser());
						System.out.println("out--exit-start-"+UserGroupInformation.getCurrentUser());
						if (fs.exists(outputFile)) {
							System.out.println("out--exit-end-"+UserGroupInformation.getCurrentUser());
							if (override) {
								System.out.println("out--delete-start-");
								fs.delete(outputFile, true);
								System.out.println("out--delete-end-");
							}
							System.out.println("out---finish"+UserGroupInformation.getCurrentUser());
						}
					} catch (IOException e) {
						System.out.println("out--delete-error-");
						e.printStackTrace();
					}
					return fs;
				}
			});
			lock.unlock();
			System.out.println("out---"+UserGroupInformation.getCurrentUser());
			ParquetOutputFormat.setOutputPath(job, outputFile.getParent());
			
		});
	}

	@Override
	public void setVersion(VERSION version) throws Exception {
		inClassloader(() -> {
			ParquetProperties.WriterVersion writerVersion;
			switch (version) {
			case VERSION_1_0:
				writerVersion = ParquetProperties.WriterVersion.PARQUET_1_0;
				break;
			case VERSION_2_0:
				writerVersion = ParquetProperties.WriterVersion.PARQUET_2_0;
				break;
			default:
				writerVersion = ParquetProperties.WriterVersion.PARQUET_2_0;
				break;
			}
			job.getConfiguration().set(ParquetOutputFormat.WRITER_VERSION, writerVersion.toString());
		});
	}

	@Override
	public void setCompression(COMPRESSION comp) throws Exception {
		inClassloader(() -> {
			CompressionCodecName codec;
			switch (comp) {
			case SNAPPY:
				codec = CompressionCodecName.SNAPPY;
				break;
			case GZIP:
				codec = CompressionCodecName.GZIP;
				break;
			case LZO:
				codec = CompressionCodecName.LZO;
				break;
			default:
				codec = CompressionCodecName.UNCOMPRESSED;
				break;
			}
			ParquetOutputFormat.setCompression(job, codec);
		});
	}

	@Override
	public void enableDictionary(boolean useDictionary) throws Exception {
		inClassloader(() -> {
			ParquetOutputFormat.setEnableDictionary(job, useDictionary);
		});
	}

	@Override
	public void setRowGroupSize(int size) throws Exception {
		inClassloader(() -> {
			ParquetOutputFormat.setBlockSize(job, size);
		});
	}

	@Override
	public void setDataPageSize(int size) throws Exception {
		inClassloader(() -> {
			ParquetOutputFormat.setPageSize(job, size);
		});
	}

	@Override
	public void setDictionaryPageSize(int size) throws Exception {
		inClassloader(() -> {
			ParquetOutputFormat.setDictionaryPageSize(job, size);
		});
	}

	@Override
	public IPentahoRecordWriter createRecordWriter() throws Exception {
		if (outputFile == null) {
			throw new RuntimeException("Output file is not defined");
		}
		if ((outputFields == null) || (outputFields.size() == 0)) {
			throw new RuntimeException("Schema is not defined");
		}

		return inClassloader(() -> {
			try {
				lock.lock();
				DataMaskingHadoopProxyUtils dataMaskingHadoopProxyUtils = new DataMaskingHadoopProxyUtils();
				UserGroupInformation ugi = dataMaskingHadoopProxyUtils
						.loginCheckAndAddConfigReturnUGI(outputFile.toUri(), job.getConfiguration());
				TaskAttemptID taskAttemptID = new TaskAttemptID("qq", 111, TaskType.MAP, 11, 11);
				TaskAttemptContextImpl task = new TaskAttemptContextImpl(job.getConfiguration(), taskAttemptID);
				ParquetRecordWriter<RowMetaAndData> recordWriter = ugi.doAs(new PrivilegedAction<ParquetRecordWriter<RowMetaAndData>>() {
					@Override
					public ParquetRecordWriter<RowMetaAndData> run() {
						try {
							FixedParquetOutputFormat nativeParquetOutputFormat = new FixedParquetOutputFormat(
									new PentahoParquetWriteSupport(outputFields));
							return (ParquetRecordWriter<RowMetaAndData>) nativeParquetOutputFormat
									.getRecordWriter(task);
						} catch (IOException | InterruptedException e) {
							e.printStackTrace();
						};
						return null;
					}
				});
				lock.unlock();
				return new PentahoParquetRecordWriter(recordWriter, task);
			} catch (IOException e) {
				throw new RuntimeException("Some error accessing parquet files", e);
			} finally {
			}
		});
	}

	public class FixedParquetOutputFormat extends ParquetOutputFormat<RowMetaAndData> {
		public FixedParquetOutputFormat(PentahoParquetWriteSupport writeSupport) {
			super(writeSupport);
		}

		@Override
		public Path getDefaultWorkFile(TaskAttemptContext context, String extension) throws IOException {
			return outputFile;
		}
	}
}
