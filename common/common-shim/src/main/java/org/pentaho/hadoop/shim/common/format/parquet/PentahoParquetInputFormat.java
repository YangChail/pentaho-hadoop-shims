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
import java.nio.file.NoSuchFileException;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.TaskAttemptID;
import org.apache.hadoop.mapreduce.task.TaskAttemptContextImpl;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.log4j.Logger;
//#if shim_type=="HDP" || shim_type=="EMR" || shim_type=="HDI" || shim_name=="mapr60"
import org.apache.parquet.hadoop.Footer;
import org.apache.parquet.hadoop.ParquetFileReader;
import org.apache.parquet.hadoop.ParquetInputFormat;
import org.apache.parquet.hadoop.ParquetRecordReader;
import org.apache.parquet.hadoop.api.ReadSupport;
import org.apache.parquet.hadoop.metadata.ParquetMetadata;
import org.apache.parquet.schema.MessageType;
//#endif
//#if shim_type=="CDH" || shim_type=="MAPR" && shim_name!="mapr60"
//$import parquet.hadoop.Footer;
//$import parquet.hadoop.ParquetFileReader;
//$import parquet.hadoop.ParquetInputFormat;
//$import parquet.hadoop.ParquetRecordReader;
//$import parquet.hadoop.api.ReadSupport;
//$import parquet.hadoop.metadata.ParquetMetadata;
//$import parquet.schema.MessageType;
//#endif
import org.pentaho.di.core.RowMetaAndData;
import org.pentaho.hadoop.shim.api.format.IParquetInputField;
import org.pentaho.hadoop.shim.api.format.IPentahoParquetInputFormat;
import org.pentaho.hadoop.shim.common.ConfigurationProxy;
import org.pentaho.hadoop.shim.common.DataMaskingHadoopProxyUtils;
import org.pentaho.hadoop.shim.common.format.HadoopFormatBase;
import org.pentaho.hadoop.shim.common.format.ReadFileFilter;
import org.pentaho.hadoop.shim.common.format.S3NCredentialUtils;

/**
 * Created by Vasilina_Terehova on 7/25/2017.
 */
public class PentahoParquetInputFormat extends HadoopFormatBase implements IPentahoParquetInputFormat {

	private static final Logger logger = Logger.getLogger(PentahoParquetInputFormat.class);

	private ParquetInputFormat<RowMetaAndData> nativeParquetInputFormat;
	private Job job;

	public PentahoParquetInputFormat() throws Exception {
		logger.info("We are initializing parquet input format");

		inClassloader(() -> {
			ConfigurationProxy conf = new ConfigurationProxy();
			job = Job.getInstance(conf);
			nativeParquetInputFormat = new ParquetInputFormat<>();
			ParquetInputFormat.setReadSupportClass(job, PentahoParquetReadSupport.class);
			ParquetInputFormat.setTaskSideMetaData(job, false);
		});
	}

	@Override
	public void setSchema(List<IParquetInputField> inputFields) throws Exception {
		ParquetInputFieldList fieldList = new ParquetInputFieldList(inputFields);
		inClassloader(() -> {
			job.getConfiguration().set(ParquetConverter.PARQUET_SCHEMA_CONF_KEY, fieldList.marshall());
		});
	}

	@Override
	public void setInputFile(String file) throws Exception {
		inClassloader(() -> {
			S3NCredentialUtils.applyS3CredentialsToHadoopConfigurationIfNecessary(file, job.getConfiguration());
			Path filePath = new Path(S3NCredentialUtils.scrubFilePathIfNecessary(file));
			lock.lock();
			DataMaskingHadoopProxyUtils dataMaskingHadoopProxyUtils = new DataMaskingHadoopProxyUtils();
			UserGroupInformation ugi = dataMaskingHadoopProxyUtils.loginCheckAndAddConfigReturnUGI(filePath.toUri(),
					job.getConfiguration());
			ugi.doAs(new PrivilegedAction<FileSystem>() {
				@Override
				public FileSystem run() {
					FileSystem fs = null;
					try {
						fs = FileSystem.get(filePath.toUri(), job.getConfiguration());
						if (!fs.exists(filePath)) {
							throw new NoSuchFileException(file);
						}
						if (fs.getFileStatus(filePath).isDirectory()) { // directory
							ParquetInputFormat.setInputPaths(job, filePath);
							ParquetInputFormat.setInputDirRecursive(job, true);
							job.getConfiguration().set(ReadFileFilter.FILTER_DIR, filePath.toString());
						} else { // file
							ParquetInputFormat.setInputPaths(job, filePath.getParent());
							ParquetInputFormat.setInputDirRecursive(job, false);
							ParquetInputFormat.setInputPathFilter(job, ReadFileFilter.class);
							job.getConfiguration().set(ReadFileFilter.FILTER_DIR, filePath.getParent().toString());
							job.getConfiguration().set(ReadFileFilter.FILTER_FILE, filePath.toString());
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
					return fs;
				}
			});
			lock.unlock();
		});
	}

	@Override
	public void setSplitSize(long blockSize) throws Exception {
		inClassloader(() -> {
			/**
			 * TODO Files splitting is temporary disabled. We need some UI checkbox for
			 * allow it, because some parquet files can't be splitted by errors in previous
			 * implementation or other things. Parquet reports source of problem only to
			 * logs, not to exception. See CorruptDeltaByteArrays.requiresSequentialReads().
			 * 
			 * mapr510 and mapr520 doesn't support SPLIT_FILES property
			 */
			// ParquetInputFormat.setMaxInputSplitSize( job, blockSize );
//#if shim_type!="MAPR"
			job.getConfiguration().setBoolean(ParquetInputFormat.SPLIT_FILES, false);
//#endif
		});
	}

	@Override
	public List<IPentahoInputSplit> getSplits() throws Exception {
		return inClassloader(() -> {
			String string = job.getConfiguration().get(ReadFileFilter.FILTER_DIR);
			List<InputSplit> splits = new ArrayList<>();
			lock.lock();
			DataMaskingHadoopProxyUtils dataMaskingHadoopProxyUtils = new DataMaskingHadoopProxyUtils();
			UserGroupInformation ugi = dataMaskingHadoopProxyUtils.loginCheckAndAddConfigReturnUGI(new URI(string),
					job.getConfiguration());
			ugi.doAs(new PrivilegedAction<FileSystem>() {
				@Override
				public FileSystem run() {
					List<InputSplit> split1s = new ArrayList<>();
					try {
						split1s = nativeParquetInputFormat.getSplits(job);
					} catch (IOException e) {
						e.printStackTrace();
					}
					splits.addAll(split1s);
					return null;
				}
			});
			lock.unlock();
			return splits.stream().map(PentahoInputSplitImpl::new).collect(Collectors.toList());
		});
	}

	// for parquet not actual to point split
	@Override
	public IPentahoRecordReader createRecordReader(IPentahoInputSplit split) throws Exception {
		return inClassloader(() -> {
			String string = job.getConfiguration().get(ReadFileFilter.FILTER_DIR);
			lock.lock();
			DataMaskingHadoopProxyUtils dataMaskingHadoopProxyUtils = new DataMaskingHadoopProxyUtils();
			UserGroupInformation ugi = dataMaskingHadoopProxyUtils.loginCheckAndAddConfigReturnUGI(new URI(string),
					job.getConfiguration());
			PentahoParquetRecordReader doAs = ugi.doAs(new PrivilegedAction<PentahoParquetRecordReader>() {
				@Override
				public PentahoParquetRecordReader run() {
					PentahoInputSplitImpl pentahoInputSplit = (PentahoInputSplitImpl) split;
					InputSplit inputSplit = pentahoInputSplit.getInputSplit();
					ReadSupport<RowMetaAndData> readSupport = new PentahoParquetReadSupport();
					ParquetRecordReader<RowMetaAndData> nativeRecordReader = new ParquetRecordReader<RowMetaAndData>(
							readSupport, ParquetInputFormat.getFilter(job.getConfiguration()));
					TaskAttemptContextImpl task = new TaskAttemptContextImpl(job.getConfiguration(),
							new TaskAttemptID());
					try {
						nativeRecordReader.initialize(inputSplit, task);
					} catch (IOException | InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					return new PentahoParquetRecordReader(nativeRecordReader);
				}
			});
			lock.unlock();
			return doAs;

		});

	}

	@Override
	public List<IParquetInputField> readSchema(String file) throws Exception {
		return inClassloader(() -> {
			ConfigurationProxy conf = new ConfigurationProxy();
			S3NCredentialUtils.applyS3CredentialsToHadoopConfigurationIfNecessary(file, conf);
			Path filePath = new Path(S3NCredentialUtils.scrubFilePathIfNecessary(file));
			lock.lock();
			DataMaskingHadoopProxyUtils dataMaskingHadoopProxyUtils = new DataMaskingHadoopProxyUtils();
			UserGroupInformation ugi = dataMaskingHadoopProxyUtils.loginCheckAndAddConfigReturnUGI(filePath.toUri(),
					conf);
			List<Footer> footers1 = new ArrayList<>();
			ugi.doAs(new PrivilegedAction<FileSystem>() {
				@Override
				public FileSystem run() {
					FileSystem fileSystem = null;
					try {
						fileSystem = FileSystem.get(filePath.toUri(), conf);
						FileStatus fileStatus = fileSystem.getFileStatus(filePath);
						System.out.println(UserGroupInformation.getCurrentUser());
						List<Footer> footers = ParquetFileReader.readFooters(conf, fileStatus, true);
						footers1.addAll(footers);
					} catch (IOException e) {
						e.printStackTrace();
					}
					return fileSystem;
				}
			});
			lock.unlock();
			if (footers1.isEmpty()) {
				return new ArrayList<IParquetInputField>();
			} else {
				ParquetMetadata meta = footers1.get(0).getParquetMetadata();
				MessageType schema = meta.getFileMetaData().getSchema();
				return ParquetConverter.buildInputFields(schema);
			}
		});
	}
}
