from cgitb import text
import hashlib
from dataclasses import dataclass
from typing import Dict, List
from models import ApkBasicInfo
import os
import subprocess
import shutil
import time

from utility import Utility
from apk_converter import APKConverter
from apk_analysis import APKAnalysis, APKAnalysisConfig

from gpapi.googleplay import GooglePlayAPI


@dataclass
class AppInspectOpsConfig():
    apk_buffer_basepath: str = None
    apk_decoded_basepath: str = None
    apk_parquet_basepath: str = None
    apk_archive_basepath: str = None
    apktool_path: str = None
    keytool_path: str = None
    jarsigner_path: str = None
    appstore_query_cli_path: str = None
    appstore_query_buffer_path: str = None
    googleplay_username: str = None
    googleplay_app_password: str = None
    googleplay_default_locale: str = None
    googleplay_default_timezone: str = None


class AppInspectOps():

    def __init__(self, ops_config: AppInspectOpsConfig, analysis_config: APKAnalysisConfig = None):
        self.config = ops_config
        self.analysis_config = analysis_config
        pass


    def analyse_apks(self, task_name: str = None, task_arguments: Dict = {}) -> Dict:
        """Perform an analytical task on the APKs converted to parquets
            Args:
                task_name: Name of the task_ functions of APKAnalysis class
                task_arguments: Arguments for the function
            Returns:
                dict: Results of the analysis
        """
        if not self.analysis_config:
            return {}
        if not task_name:
            return {}
        if not task_name.startswith("task_"):
            return {}
        analysis = APKAnalysis(self.analysis_config)
        task_func_to_call = getattr(analysis, task_name)
        final_results = task_func_to_call(**task_arguments)
        del analysis
        return final_results


    @dataclass
    class ApkConversionInfo():
        parquet_fullpath: str = None
        parquet_basename: str = None
        apk_in_archive_fullfilename: str = None
        apk_in_archive_base_filename: str = None
        basic_info: ApkBasicInfo = None
        signature_verified: bool = False
        signed_by_certificate: str = None

    def convert_and_move_apk(self, apk_filename: str, is_absolute_filepath: bool = False) -> ApkConversionInfo:
        """Decode and convert an APK file to the Parquet format and move the APK file to archive 
            Args:
                apk_filename: Path of an APK file
                is_relative_filepath: whether the apk_filename is a relative path to the apk_buffer_basepath
            Returns:
                str: Path of the Parquet directory/file
        """
        if not is_absolute_filepath:
            apk_filename = os.path.join(self.config.apk_buffer_basepath, apk_filename)

        if (not os.path.exists(apk_filename)) or (not os.path.isfile(apk_filename)):
            raise Exception("APK file does not exist")

        if not os.path.exists(self.config.apk_decoded_basepath):
            os.mkdir(self.config.apk_decoded_basepath)

        apk_hash_full = Utility.get_file_hash_sha256(apk_filename)
        apk_hash_partial = apk_hash_full[0:12]
        apk_extracted_path = os.path.join(self.config.apk_decoded_basepath, apk_hash_full)

        if os.path.exists(apk_extracted_path):
            if os.path.isdir(apk_extracted_path):
                shutil.rmtree(apk_extracted_path)
            elif os.path.isfile(apk_extracted_path):
                os.remove(apk_extracted_path)

        # Step 1: Use apktool to extract / decode the APK
        apktool_result = subprocess.run([self.config.apktool_path,
                                         "d", 
                                         apk_filename,
                                         "--output", apk_extracted_path,
                                         "--force-all"],
                                         capture_output=True)

        if apktool_result.returncode != 0:
            raise Exception(f"APK extraction failed - {apktool_result.stderr} {apktool_result.stdout}")

        if not os.path.exists(apk_extracted_path):
            raise Exception(f"APK extraction failed - No extraction directory")

        jarsigner_result = subprocess.run([self.config.jarsigner_path,
                                            "-verify",
                                            apk_filename],
                                            capture_output=True, text=True)

        apk_signature_verified = False

        if jarsigner_result.returncode == 0:
            apk_signature_verified = "jar verified." in jarsigner_result.stdout

        apktool_result = subprocess.run([self.config.keytool_path,
                                            "-printcert", 
                                            "-jarfile", 
                                            apk_filename],
                                            capture_output=True, text=True)

        if apktool_result.returncode == 0:
            certificate_summary = apktool_result.stdout

        # Step 2: Convert the extracted APK (directory) to Parquet
        apk_converter = APKConverter()
        apk_basicinfo = apk_converter.get_apk_basicinfo(apk_extracted_path)
        apk_basicinfo.apk_sha256 = apk_hash_full
        apk_parquet_path = apk_converter.convert_apk_to_parquet(apk_extracted_path, self.config.apk_parquet_basepath, apk_hash_full)

        if not os.path.exists(apk_parquet_path):
            apk_parquet_path = None

        # Step 3: Move the APK file to archive and remove the extracted directory
        apk_archive_path = os.path.join(self.config.apk_archive_basepath, f"{apk_basicinfo.app_id}-{apk_basicinfo.version_code}-{apk_hash_partial}.apk")
        shutil.move(apk_filename, apk_archive_path)
        shutil.rmtree(apk_extracted_path, ignore_errors=True)

        return self.ApkConversionInfo(parquet_fullpath=apk_parquet_path,
                                        parquet_basename=os.path.basename(apk_parquet_path),
                                        apk_in_archive_fullfilename=apk_archive_path,
                                        apk_in_archive_base_filename=os.path.basename(apk_archive_path),
                                        basic_info=apk_basicinfo,
                                        signature_verified=apk_signature_verified,
                                        signed_by_certificate=certificate_summary)


    def query_googleplay(self, query_method: str, query_json_string: str) -> str:
        """Invoke app-store-query-cli to relay the query to Google Play
            For usage, see https://github.com/jason-chao/app-store-query-cli 
            Args:
                query_method: Query method
                query_json_string: The query formatted in Json string
            Returns:
                str: The result formatted in Json string
        """

        if not os.path.exists(self.config.appstore_query_buffer_path):
            os.mkdir(self.config.appstore_query_buffer_path)

        request_hash = hashlib.sha256(query_json_string.encode()).hexdigest()
        timestamp = str(time.time()).replace(".", "")
        query_base_filename = f"{timestamp}_{request_hash[0:12]}_q.json"
        result_base_filename = f"{timestamp}_{request_hash[0:12]}_r.json"
        query_filename = os.path.join(self.config.appstore_query_buffer_path, query_base_filename)
        result_filename = os.path.join(self.config.appstore_query_buffer_path, result_base_filename)

        with open(query_filename, "w") as f:
            f.write(query_json_string)
            f.close()

        storequery_result = subprocess.run([self.config.appstore_query_cli_path,
                                            "--store-name", "google-play",
                                            "--method", query_method,
                                            "--query-file", query_filename,
                                            "--output-file", result_filename],
                                            capture_output=True)

        if storequery_result.returncode != 0:
            raise Exception(f"Google Play query failed - {storequery_result.stderr} {storequery_result.stdout}")

        if not os.path.exists(result_filename):
            raise Exception(f"Google Play query failed - no result file")

        result = None
        with open(result_filename, "r") as f:
            result = f.read()
            f.close()

        os.remove(query_filename)
        os.remove(result_filename)

        return result


    @dataclass
    class ApkFileInfo():
        base_filename: str = None
        full_filename: str = None
        file_sha256: str = None


    def retrieve_apk(self, appid: str, custom_gplay_locale: str = None, custom_gplay_timezone: str = None) -> ApkFileInfo:
        """Retrieve an APK file from Google Play
            Args:
                appid: id of the Android application
                custom_gplay_locale: locale setting for Google Play (if not set, the default value the config will be used)
                custom_gplay_timezone: timezone setting for Google Play (if not set, the default value in the config will be used)
            Returns:
                str: Base filename of the APK downloaded to apk_buffer_basepath
        """
        timestamp = str(time.time()).replace(".", "")
        target_base_filename = f"{appid}-{timestamp}.apk"
        target_filename = os.path.join(self.config.apk_buffer_basepath, target_base_filename)

        if os.path.exists(target_filename):
            raise Exception("Buffer APK file exists")

        gplay_locale = self.config.googleplay_default_locale
        gplay_timezone = self.config.googleplay_default_timezone

        if custom_gplay_locale is not None:
            gplay_locale = custom_gplay_locale
        
        if custom_gplay_timezone is not None:
            gplay_timezone = custom_gplay_timezone

        gplay_client = GooglePlayAPI(locale=gplay_locale, timezone=gplay_timezone)
        gplay_client.login(self.config.googleplay_username, self.config.googleplay_app_password, None, None)

        apkdata = gplay_client.download(appid)

        with open(target_filename, "wb") as apk_file:
            for chunk in apkdata.get("file").get("data"):
                apk_file.write(chunk)

        if not os.path.exists(target_filename):
            raise Exception("APK writing failed")

        return self.ApkFileInfo(base_filename=os.path.basename(target_filename),
                                    full_filename=target_filename,
                                    file_sha256=Utility.get_file_hash_sha256(target_filename))
