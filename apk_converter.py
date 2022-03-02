import dataclasses
from typing import List
import multiprocessing
from multiprocessing import Pool
from typing import NoReturn
import hashlib
import pandas as pd
import pyarrow
import pyarrow.parquet
import xml.etree.ElementTree as ET
import os

from models import ApkBasicInfo, ApkContentFileInfo
from utility import Utility

class APKConverter:
    """ AppInspect Converter
        The class is for converting extracted Android Application Package (APKs) to the Parquet format
    """

    def __init__(self):
        self.ext_store_as_text = ["smali", "json", "xml", "txt", "log", "html", "htm", "js", "css", "yaml", "yml", "csv"]


    def convert_apk_to_parquet(self, apk_path: str, parquet_base_path: str, apk_sha256: str) -> str:
        """Convert an APK file to the Parquet format
            Args:
                apk_path: Path of the directory to which the apk is extracted
            Returns:
                str: Path of the Parquet directory/file
        """
        apk_basicinfo = self.get_apk_basicinfo(apk_path)
        apk_basicinfo.apk_sha256 = apk_sha256
        content_file_list = self.get_apk_content_file_list(apk_path)
        path = self.write_as_parquet(apk_basicinfo, content_file_list, parquet_base_path)
        return path


    def get_apk_basicinfo(self, apk_path: str) -> ApkBasicInfo:
        """Extract app id, version name and version code from an apk
            Args:
                apk_path: Path of the directory to which the apk is extracted
            Returns:
                ApkBasicInfo
        """
        manifest_path = os.path.join(apk_path, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            raise Exception("AndroidManifest XML does not exist")
        manifest_root = ET.parse(manifest_path).getroot()
        apk_basicinfo = ApkBasicInfo()
        apk_basicinfo.app_id = manifest_root.get("package")
        apk_basicinfo.version_code = manifest_root.get("android:versionCode")
        apk_basicinfo.version_name = manifest_root.get("android:versionName")
        # read version info from APKTool's yaml output if it is not found in Manifest
        if apk_basicinfo.version_code is None or apk_basicinfo.version_name is None:
            apktool_yaml_path = os.path.join(apk_path, "apktool.yml")
            import yaml
            # APKTool's '!!' labelling output is not recognised PyYAML.  The label must be removed before parsing.
            apktool_yaml = yaml.safe_load("\n".join([line for line in open(apktool_yaml_path, "r").readlines() if not line.startswith("!!")]))
            apk_basicinfo.version_code = apktool_yaml["versionInfo"]["versionCode"]
            apk_basicinfo.version_name = apktool_yaml["versionInfo"]["versionName"]
        if not isinstance(apk_basicinfo.version_code, int):
            apk_basicinfo.version_code = int(apk_basicinfo.version_code)
        return apk_basicinfo


    def read_apk_content_file(self, filename: str, apk_path: str) -> ApkContentFileInfo:
        """Read a single file contained in an apk
            Args:
                filename: Path of the file (full path) 
                apk_path: Path of the directory to which the apk is extracted
            Returns:
                ApkContentFileInfo
        """
        relative_path = filename.split(apk_path)[-1]
        base_filename = relative_path.split(os.path.sep)[-1]
        base_filename_ext = base_filename.split(".")[-1]
        content_text = None
        content_blob = None
        content_mode = "blob"

        with open(filename, "rb") as f:
            content_blob = f.read()
        file_hash = hashlib.sha256(content_blob).hexdigest()
        content_mode = "blob"

        try:
            # Try to read the file as text.
            # It is entirely normal that some files bearing a text-file extension may not be read as text.
            # The un-decoded "AndroidManifest.xml" is an example.
            # In this case, just keep the content in binary mode.
            if base_filename_ext.lower() in self.ext_store_as_text:
                with open(filename, "r") as f:
                    content_text = f.read()
                content_blob = None
                content_mode = "text"
        except UnicodeDecodeError:
            pass

        file_obj = ApkContentFileInfo (relative_path=relative_path,
                                      filename=base_filename,
                                      extension=base_filename_ext,
                                      content_text=content_text,
                                      content_blob=content_blob,
                                      content_mode=content_mode,
                                      file_sha256=file_hash)

        return file_obj


    def get_apk_content_file_list(self, apk_path: str) -> List[ApkContentFileInfo]:
        """Read all files in contained in an apk 
            Args:
                apk_path: Path of the directory to which the apk is extracted
            Returns:
                List[ApkContentFileInfo]
        """
        if not os.path.exists(apk_path) or not os.path.isdir(apk_path):
            raise Exception("APK path may be invalid")
        all_content_filenames = Utility.get_all_files_in_dir(apk_path)
        pool = Pool(multiprocessing.cpu_count())
        file_content_list = pool.starmap(self.read_apk_content_file, [(filename, apk_path) for filename in all_content_filenames])
        return file_content_list


    def apk_sha256_exists(self, table: pyarrow.Table, apk_hash_sha256) -> bool:
        """Check whether an APK hash exists in a Table read from a Parquet file 
            Args:
                table: Pyarrow Table loaded from a Parquet directory/file
            Returns:
                bool: True if the hash exists; otherwise False
        """
        return (table.filter(pyarrow.compute.equal(table["apk_sha256"], apk_hash_sha256)).num_rows > 0)


    def write_as_parquet(self, apk_basicinfo: ApkBasicInfo, content_file_list: List[ApkContentFileInfo], parquet_base_path: str, append_if_exists=True, partition_cols=["content_mode"]) -> str:
        """Write a list of file contents extracted from an APK to a Parquet file/directory
            Args:
                apk_basicinfo: ApkBasicInfo
                content_file_list: List of ApkContentFileInfo
                parquet_base_path: The base path where the Parquet directories/files are stored
                append_if_exists: If True, a newer/older version of an APK is appended to the Parquet directory/file; If False, any exisiting Parquet directory/file will be overwritten.
                partition_cols: Partitioning setting for writing to a Parquet directory 
            Returns:
                bool: True if the version code exists; otherwise False
        """
        pd_content_df = pd.DataFrame([{**apk_basicinfo.__dict__, **cf.__dict__} for cf in content_file_list])
        pyarrow_content_table = pyarrow.Table.from_pandas(pd_content_df)
        apk_parquet_path = os.path.join(parquet_base_path, apk_basicinfo.app_id)
        if append_if_exists:
            if os.path.exists(apk_parquet_path):
                exisiting_pyarrow_table = pyarrow.parquet.read_table(apk_parquet_path)
                if not self.validate_apk_content_table(exisiting_pyarrow_table):
                    raise Exception("Schema of the exisiting table is invalid")
                if self.apk_sha256_exists(exisiting_pyarrow_table, apk_basicinfo.apk_sha256):
                    raise Exception("This APK already exists in the exisiting table.  Hash of the APK file is detected.")
        else:
            Utility.remove_file_or_dir_if_exists(apk_parquet_path)
        pyarrow.parquet.write_to_dataset(pyarrow_content_table, apk_parquet_path, flavor="spark", partition_cols=partition_cols)
        return apk_parquet_path


    def validate_apk_content_table(self, table: pyarrow.Table) -> bool:
        """Validate whether a Table read from a Parquet directory/file contains all the columns of data models ApkBasicInfo and ApkContentFileInfo
            Args:
                table: Pyarrow Table loaded from a Parquet directory/file
            Returns:
                bool: True if the Table contains all the columns; otherwise, False
        """
        return (all([field.name in table.column_names for field in dataclasses.fields(ApkBasicInfo)]) and 
                all([field.name in table.column_names for field in dataclasses.fields(ApkContentFileInfo)]))
