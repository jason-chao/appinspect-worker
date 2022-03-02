from typing import List, Dict, Callable, Tuple
import findspark
from dataclasses import dataclass
import os
from pyspark.sql import SparkSession, DataFrame, group
from pyspark.sql import functions as sfunc
from pyspark.sql.types import StringType
import json
import itertools
import re
import hashlib
from datetime import datetime

@dataclass
class APKAnalysisConfig():
    java_home: str = None
    spark_home: str = None
    spark_master: str = "local"
    apk_parquet_basepath: str = None


@dataclass
class APKAnalysisResult():
    total: int = 0
    output_limit: int = 0
    records: List = None


@dataclass
class TrackerEntry():
    name: str = None
    domain_names: List = None
    class_signatures: List = None
    source: str = None


class APKAnalysis():

    def __init__(self, config: APKAnalysisConfig):
        self.config = config
        os.environ["JAVA_HOME"] = self.config.java_home
        os.environ["SPARK_HOME"] = self.config.spark_home

        app_suffix = "_" + hashlib.sha256(bytes(str(datetime.now()),"ascii")).hexdigest()[:8]

        findspark.init()
        self.spark = SparkSession.builder \
                        .master(self.config.spark_master) \
                        .appName(APKAnalysis.__name__ + app_suffix) \
                        .getOrCreate()
        self.spark.sparkContext.addPyFile("apk_analysis.py")
        pass


    # def __del__(self):
    #    self.spark.stop()


    def task_permission_scan(self, app_parquet_basenames: List = ["*"], limit: int = 500) -> Dict:

        df = self.read_parquets(app_parquet_basenames, "content_mode=text")

        permission_protection_level_map = self.load_permission_protection_level_map()

        df = df.filter(df["relative_path"] == "/AndroidManifest.xml")
        df = self.split_text_content_into_lines(df).drop("content_text").drop("content_blob")
        df = df.filter(df["line"].contains("permission ")).filter(df["line"].contains(" android:name=\""))

        df = df.withColumn("permission", sfunc.regexp_extract(sfunc.col("line"), "android:name=\"([a-zA-Z0-9_\.]+)\"", 1))

        protection_name_list = list(permission_protection_level_map.keys())
        get_protection_level_func = sfunc.udf(lambda permission_name: permission_protection_level_map[permission_name] if permission_name in protection_name_list else "unidentified", StringType())

        df = df.withColumn("protection_level", get_protection_level_func(df["permission"]))

        agg_funcs = [sfunc.collect_list("permission").alias("permissions"), sfunc.collect_list("protection_level").alias("protection_levels")]

        groupped_df = self.group_by_app_and_version(df, agg_funcs)

        final_results = self.get_result_obj(groupped_df, limit)

        return final_results.__dict__


    def task_url_extraction(self, app_parquet_basenames: List = ["*"], limit: int = 500) -> Dict:

        df = self.read_parquets(app_parquet_basenames, "content_mode=text")

        df = self.filter_by_extension(df, ["smali"]).filter(df["content_text"].contains("const-string"))

        df = self.split_text_content_into_lines(df)

        df = df.filter(df["line"].contains("const-string")).filter(df["line"].contains("http://") | df["line"].contains("https://"))

        df = df.withColumn("url", sfunc.regexp_extract(sfunc.col("line"), "(https?):\/[-a-zA-Z0-9+&@#\/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#\/%=~_|]", 0))

        # remove empty urls
        df = df.filter(df["url"] != "https://").filter(df["url"] != "http://")

        df = df.withColumn("domain", sfunc.regexp_extract(sfunc.col("url"), "(https?):\/\/([-a-zA-Z0-9+&@#%?=~_|!:,.;]+)\/", 2))

        # remove invalid FQDNs
        df = df.filter(sfunc.col("domain").rlike("^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"))

        df = self.add_column_class_name(df)

        agg_funcs = [sfunc.collect_set("url").alias("urls"), sfunc.collect_set("domain").alias("domains"), self.get_aggregator_func_class_names_list(), self.get_aggregator_func_lines()]

        groupped_df = self.group_by_app_and_version(df, agg_funcs)

        final_results = self.get_result_obj(groupped_df, limit)

        return final_results.__dict__


    def task_tracker_classname_scan(self, app_parquet_basenames: List = ["*"], tracker_list_name: str = None, limit: int = 500) -> Dict:

        if not tracker_list_name:
            return APKAnalysisResult().__dict__

        tracker_list = self.load_tracker_list(tracker_list_name)
        classname_tracker_map = self.get_classname_to_tracker_map(tracker_list)
        classname_list = list(classname_tracker_map.keys())

        regex_escaped_tracker_classname_list = ["^(" + classname.replace(".", "\.") + ")" for classname in classname_list]

        df = self.read_parquets(app_parquet_basenames, "content_mode=text")

        df = self.filter_by_extension(df, ["smali"])

        df = self.add_column_class_name(df)

        df = df.filter(sfunc.col("class_name").rlike("|".join(regex_escaped_tracker_classname_list)))

        extract_tracker_classname_func = sfunc.udf(lambda class_name: identify_matching_criterion(class_name, classname_list), StringType())
        df = df.withColumn("matching_classname", extract_tracker_classname_func(df["class_name"]))

        get_tracker_name_func = sfunc.udf(lambda classname: classname_tracker_map[classname] if classname in classname_tracker_map else f"(not detected for {classname})", StringType())
        df = df.withColumn("tracker_name", get_tracker_name_func(df["matching_classname"]))

        agg_funcs = [sfunc.collect_set("tracker_name").alias("trackers")]

        groupped_df = self.group_by_app_and_version(df, agg_funcs).withColumn("tracker_list", sfunc.lit(tracker_list_name))

        final_results = self.get_result_obj(groupped_df, limit)

        return final_results.__dict__


    def task_tracker_domain_scan(self, app_parquet_basenames: List = ["*"], tracker_list_name: str = None, limit: int = 500) -> Dict:

        if not tracker_list_name:
            return APKAnalysisResult().__dict__

        tracker_list = self.load_tracker_list(tracker_list_name)
        domain_tracker_map = self.get_domain_to_tracker_map(tracker_list)
        domain_list = list(domain_tracker_map.keys())
        regex_escaped_domain_list = ["(" + domain.replace(".", "\.") + ")" for domain in domain_list if "." in domain]

        df = self.read_parquets(app_parquet_basenames, "content_mode=text")

        df = self.filter_by_extension(df, ["smali"]).filter(df["content_text"].contains("const-string"))

        df = self.split_text_content_into_lines(df)

        df = df.filter(df["line"].contains("const-string")).filter(df["line"].contains("http"))

        df = df.filter(sfunc.lower(sfunc.col("line")).rlike("|".join(regex_escaped_domain_list)))

        extract_tracker_domain_func = sfunc.udf(lambda content_line: identify_matching_criterion(content_line, domain_list), StringType())
        df = df.withColumn("matching_domain", extract_tracker_domain_func(df["line"]))

        get_tracker_name_func = sfunc.udf(lambda domain_name: domain_tracker_map[domain_name] if domain_name in domain_tracker_map else f"(not detected for {domain_name})", StringType())
        df = df.withColumn("tracker_name", get_tracker_name_func(df["matching_domain"]))

        df = self.add_column_class_name(df)

        agg_funcs = [self.get_aggregator_func_class_names_list(), self.get_aggregator_func_lines(), sfunc.collect_set("tracker_name").alias("trackers"), sfunc.collect_set("matching_domain").alias("domains")]

        groupped_df = self.group_by_app_and_version(df, agg_funcs).withColumn("tracker_list", sfunc.lit(tracker_list_name))

        final_results = self.get_result_obj(groupped_df, limit)

        return final_results.__dict__



    def task_text_search(self, app_parquet_basenames: List = ["*"], search_terms: List = [], extensions: List = None, filename: str = None, case_sensitive: bool = False, limit: int = 500) -> Dict:

        if not search_terms:
            return APKAnalysisResult().__dict__

        if len(search_terms) <= 0:
            return APKAnalysisResult().__dict__

        df = self.read_parquets(app_parquet_basenames, "content_mode=text")

        for term in search_terms:
            df = self.filter_by_text_containing(df, term, case_sensitive)

        if extensions:
            df = self.filter_by_extension(df, extensions)

        if filename:
            df = self.filter_by_path_containing(df, filename, case_sensitive)

        agg_funcs = [self.get_aggregator_func_relative_paths()]

        groupped_df = self.group_by_app_and_version(df, agg_funcs)

        final_results = self.get_result_obj(groupped_df, limit)

        return final_results.__dict__


    def task_code_scan(self, app_parquet_basenames: List = ["*"], search_terms: List = [], package_name: str = None, with_inferred_developers: bool = True, with_class_name: bool = True, case_sensitive: bool = False, limit: int = 500) -> Dict:

        if not search_terms:
            return APKAnalysisResult().__dict__

        if len(search_terms) <= 0:
            return APKAnalysisResult().__dict__

        df = self.read_parquets(app_parquet_basenames, "content_mode=text")

        df = self.filter_by_extension(df, ["smali"])

        if package_name :
            df = self.filter_by_classname_containing(df, package_name, case_sensitive)

        for term in search_terms:
            df = self.filter_by_text_containing(df, term, case_sensitive)

        df = self.split_text_content_into_lines(df)

        for term in search_terms:
            df = self.filter_by_line_text_containing(df, term, case_sensitive)

        agg_funcs = [self.get_aggregator_func_lines()]
        
        if with_inferred_developers:
            df = self.add_column_inferred_developer(df)
            agg_funcs.append(self.get_aggregator_func_inferred_developers())

        if with_class_name:
            df = self.add_column_class_name(df)
            agg_funcs.append(self.get_aggregator_func_class_names_list())
        
        groupped_df = self.group_by_app_and_version(df, agg_funcs)

        # if with_inferred_developers:
        #    groupped_df = self.add_column_array_length(groupped_df, "inferred_developers", "inferred_developer_count")
        
        final_results = self.get_result_obj(groupped_df, limit)

        return final_results.__dict__



    def get_result_obj(self, df: DataFrame, limit: int = 500) -> APKAnalysisResult():
        result_obj = APKAnalysisResult()
        if limit > 0:
            df = df.limit(limit)
        result_obj.records = self.convert_to_dict(df)
        result_obj.total = len(result_obj.records)
        result_obj.output_limit = limit
        return result_obj


    def read_parquets(self, parquet_basenames: List = [], partition: str = "*", parquet_basepath: str = None) -> DataFrame:
        if parquet_basepath is None:
            parquet_basepath = self.config.apk_parquet_basepath
        parquet_list = [os.path.join(parquet_basepath, basename, partition) for basename in parquet_basenames]
        return self.spark.read.parquet(*parquet_list)

    
    def split_text_content_into_lines(self, df: DataFrame):
        return df.withColumn("line", sfunc.explode(sfunc.split(df["content_text"], "\n"))).drop("content_text")


    def filter_by_sql_conditions(self, df: DataFrame, conditions_in_sql: str) -> DataFrame:
        return df.filter(conditions_in_sql)


    def filter_by_text_containing(self, df: DataFrame, text: str, case_sensitive: bool = False) -> DataFrame:
        if case_sensitive:
            return df.filter(df["content_text"].contains(text))
        else:
            return df.filter(sfunc.lower(df["content_text"]).contains(text.lower()))


    def filter_by_line_text_containing(self, df: DataFrame, text: str, case_sensitive: bool = False) -> DataFrame:
        if case_sensitive:
            return df.filter(df["line"].contains(text))
        else:
            return df.filter(sfunc.lower(df["line"]).contains(text.lower()))


    def filter_by_extension(self, df: DataFrame, extensions: List, case_sensitive: bool = False) -> DataFrame:
        if len(extensions) <= 0:
            return df
        if case_sensitive:
            return df.filter(df["extension"].isin(extensions))
        else:
            extensions = list([ext.lower() for ext in extensions])
            return df.filter(sfunc.lower(df["extension"]).isin(extensions))


    def filter_by_classname_containing(self, df: DataFrame, name: str, case_sensitive: bool = False) -> DataFrame:
        name = name.replace(".", os.path.sep)
        return self.filter_by_path_containing(df, name, case_sensitive)


    def filter_by_path_containing(self, df: DataFrame, name: str, case_sensitive: bool = False) -> DataFrame:
        if case_sensitive:
            return df.filter(df["relative_path"].contains(name))
        else:
            return df.filter(sfunc.lower(df["relative_path"]).contains(name.lower()))


    def add_column_array_length(self, df: DataFrame, array_column_name: str = None, new_column_name: str = "array_count") -> DataFrame:
        return df.withColumn(new_column_name, sfunc.size(df[array_column_name]))


    def add_column_inferred_developer(self, df: DataFrame) -> DataFrame:
        infer_developer_func = sfunc.udf(lambda package_path: infer_developer_from_packagename(package_path), StringType())
        return df.withColumn("inferred_developer", infer_developer_func(df["relative_path"]))


    def add_column_class_name(self, df: DataFrame) -> DataFrame:
        get_class_name_func = sfunc.udf(lambda package_path: get_class_full_name(package_path), StringType())
        return df.withColumn("class_name", get_class_name_func(df["relative_path"]))


    def group_by_app_and_version(self, df: DataFrame, aggregator_funcs: List = []) -> DataFrame:
        return df.groupBy("app_id", "version_name", "version_code", "apk_sha256").agg(*aggregator_funcs)

    
    def get_aggregator_func_row_count(self, new_column_name: str = "count") -> Callable:
        return sfunc.count(sfunc.lit(1)).alias(new_column_name)
    
    def get_aggregator_func_inferred_developers(self) -> Callable:
        return sfunc.collect_set("inferred_developer").alias("inferred_developers")
    
    def get_aggregator_func_class_names_list(self) -> Callable:
        return sfunc.collect_list("class_name").alias("classes")
    
    def get_aggregator_func_class_names_set(self) -> Callable:
        return sfunc.collect_set("class_name").alias("classes")

    def get_aggregator_func_relative_paths(self) -> Callable:
        return sfunc.collect_set("relative_path").alias("paths")

    def get_aggregator_func_lines(self) -> Callable:
        return sfunc.collect_list("line").alias("lines")

    def convert_to_dict(self, df: DataFrame) -> Dict:
        return df.toPandas().to_dict(orient="records")

    def load_tracker_list(self, source_name: str) -> List:
        with open("full_tracker_list.json", "r") as file:
            tracker_list = json.loads(file.read())
            return list([TrackerEntry(**tracker) for tracker in tracker_list if tracker["source"] == source_name])

    def load_permission_protection_level_map(self) -> Dict:
        with open("android_permission_levels.json", "r") as file:
            return json.loads(file.read())

    def get_domain_to_tracker_map(self, tracker_list: List) -> Dict:
        domain_trackers = [list([{ "domain": domain, "tracker_name": tracker.name } for domain in tracker.domain_names]) for tracker in tracker_list if len(tracker.domain_names) > 0]
        domain_trackers = list(itertools.chain.from_iterable(domain_trackers))
        domain_tracker_map = {}
        for tracker in domain_trackers:
            if tracker["domain"] not in domain_tracker_map.keys():
                domain_tracker_map[tracker["domain"]] = tracker["tracker_name"]
        return domain_tracker_map

    def get_classname_to_tracker_map(self, tracker_list: List) -> Dict:
        classname_trackers = [list([{ "class_fragment": class_signature, "tracker_name": tracker.name } for class_signature in tracker.class_signatures]) for tracker in tracker_list if len(tracker.class_signatures) > 0]
        classname_trackers = list(itertools.chain.from_iterable(classname_trackers))
        classname_tracker_map = {}
        for tracker in classname_trackers:
            if tracker["class_fragment"] not in classname_tracker_map.keys():
                classname_tracker_map[tracker["class_fragment"]] = tracker["tracker_name"]
        return classname_tracker_map


def get_class_full_name(package_relative_path: str) -> str:
    segments = [seg for seg in package_relative_path.split(os.path.sep) if len(seg) > 0][1:]
    if len(segments) <= 0:
        return None
    segments[-1] = segments[-1].replace(".smali", "")
    return ".".join(segments)


def infer_developer_from_packagename(package_relative_path: str) -> str:
    original_tlds  = ["com", "org", "net", "int", "edu", "gov", "mil"]
    segments = package_relative_path.split(os.path.sep)
    for i in range(0, (len(segments) - 1)):
        if segments[i] in original_tlds:
            if i < (len(segments) - 1):
                return segments[i + 1]
    return None


def identify_matching_criterion(line: str, criterion_list: List, case_insensitive: bool = True) -> str:
    if case_insensitive:
        line = line.lower()
    regex_signs = ["*", "..", "\\", "?", "{", "}", "[", "]", "+", "^", "$", "=", ">", "!", "&"]
    for criterion in criterion_list:
        criterion_in_original_case = criterion
        if case_insensitive:
            criterion = criterion.lower()
        criterion_is_regex = False
        for sign in regex_signs:
            if sign in criterion:
                criterion_is_regex = True
                break
        if criterion_is_regex:
            criterion_regex_matcher = re.compile(criterion.replace(".", "\."))
            if criterion_regex_matcher.search(line) is not None:
                return criterion_in_original_case
        elif criterion in line:
            return criterion_in_original_case
    return None
