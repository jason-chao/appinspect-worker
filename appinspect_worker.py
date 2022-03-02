#!/usr/bin/env python3

from dataclasses import dataclass, field
import logging
from typing import List, Dict, Tuple
import yaml
import json
import sys
import threading
from queue import PriorityQueue
import time
import random
import dataclasses
from urllib.parse import urljoin

from signalrcore.hub_connection_builder import HubConnectionBuilder
import requests

from appinspect_ops import AppInspectOps, AppInspectOpsConfig
from apk_analysis import APKAnalysisConfig

@dataclass
class AppInspectWorkerConfig():
    service_rpc_url: str = None
    service_api_base_url: str = None


@dataclass
class AppInspectActionInfo():
    op_method: str = None
    required_parameters: List[str] = field(default_factory=List)
    parameters_to_be_removed: List[str] = None
    enabled: bool = True
    max_threads: int = 1
    invocation_spacing_range_sec: Tuple = None


logging.basicConfig(level=logging.INFO)
default_unified_config_filename = "appinspect_worker_config.yml"

action_info_list = [AppInspectActionInfo(op_method="query_googleplay", enabled=True, required_parameters=["query_method", "query_json_string"], parameters_to_be_removed=["automatic_apk_retrieval"], max_threads=1, invocation_spacing_range_sec=(3,7)),
                    AppInspectActionInfo(op_method="retrieve_apk", enabled=True, required_parameters=["appid"], max_threads=1, invocation_spacing_range_sec=(5,10)),
                    AppInspectActionInfo(op_method="convert_and_move_apk", enabled=True, required_parameters=["apk_filename"], max_threads=1, invocation_spacing_range_sec=None),
                    AppInspectActionInfo(op_method="analyse_apks", enabled=True, required_parameters=["task_name", "task_arguments"], max_threads=1, invocation_spacing_range_sec=None)]

supported_actions = list([ai.op_method for ai in action_info_list if ai.enabled])


class AppInspectWorker():

    def __init__(self, worker_config: AppInspectWorkerConfig, ops_config: AppInspectOpsConfig, apk_analysis: APKAnalysisConfig = None):
        self.worker_config = worker_config
        self.ops_config = ops_config
        self.apk_analysis_config = apk_analysis
        self.is_rpcworker_registered = False
        if self.apk_analysis_config:
            self.ops = AppInspectOps(self.ops_config, self.apk_analysis_config)
        else:
            self.ops = AppInspectOps(self.ops_config)
        self.hub = HubConnectionBuilder()\
                   .with_url(self.worker_config.service_rpc_url)\
                   .with_automatic_reconnect({"type":"raw", "keep_alive_interval": 10, "reconnect_interval": 5, "max_attempts": sys.maxsize})\
                   .build()
        self.hub.on_open(lambda: (logging.info(f"RPC connection is open"), self.hub.send("RegisterWorker", [])))
        self.hub.on_close(lambda: logging.info("RPC connection is closed"))
        self.hub.on_error(lambda error_message: logging.info(f"RPC error: {error_message}"))
        self.hub.on("WorkerRegistered", lambda result: (self.method_worker_registered(result[0]), self.hub.send("GetPendingTasks", [])))
        self.hub.on("AssignTask", lambda method_args: self.method_assign_task(method_args[0], method_args[1], method_args[2], method_args[3]))
        self.hub.on("PendingTasks", lambda pending_tasks: self.method_pending_tasks(pending_tasks[0]))
        self.hub_lock = threading.Lock()
        self.busy_threads = 0
        self.action_queues = {}
        self.threads = []
        for action_info in action_info_list:
            self.action_queues[action_info.op_method] = PriorityQueue()
            for i in range(action_info.max_threads):
                thread = threading.Thread(target=self.run_task_daemon, args=(action_info.op_method,action_info.invocation_spacing_range_sec), daemon=True)
                thread.start()
                self.threads.append(thread)
        pass


    def run_task_daemon(self, action_name: str, invocation_spacing_sec: Tuple = None):
        while True:
            (_, (task_id, task_arguments_json_str)) = self.action_queues[action_name].get()
            self.busy_threads += 1
            self.run_task(task_id, action_name, task_arguments_json_str)
            self.action_queues[action_name].task_done()
            self.busy_threads -= 1
            if isinstance(invocation_spacing_sec, tuple):
                time.sleep(random.randint(invocation_spacing_sec[0], invocation_spacing_sec[1]))
        pass


    def run_task(self, task_id: str, action_name: str, task_arguments_json_str: str):
        logging.info(f"Running task {task_id} of {action_name}")
        task_arguments = json.loads(task_arguments_json_str)
        action_info = get_action_info_by_name(action_name)

        if action_info is None:
            self.task_error_raised(task_id, "Invalid action name")
            return

        if not all([rp in task_arguments for rp in action_info.required_parameters]):
            self.task_error_raised(task_id, "Missing required parameters")
            return

        if action_info.parameters_to_be_removed:
            for parameter_name_for_removal in action_info.parameters_to_be_removed:
                if parameter_name_for_removal in task_arguments:
                    del task_arguments[parameter_name_for_removal]

        function_to_call = getattr(self.ops, action_info.op_method)

        try:
            result = function_to_call(**task_arguments)
            if not isinstance(result, str):
                if dataclasses.is_dataclass(result):
                    result = dataclasses.asdict(result)
                result = json.dumps(result)
            postresp = requests.post(url=urljoin(self.worker_config.service_api_base_url, f"task/{task_id}"), data={"result": result})
            if postresp.status_code == 200:
                with self.hub_lock:
                    self.hub.send("CompleteTask", [task_id, None])
                logging.info(f"Completed task {task_id} of {action_name}")
            else:
                raise Exception(f"Result upload error {postresp.status_code} : {postresp.content}")
        except BaseException as ex:
            self.task_error_raised(task_id, f"{ex} - {type(ex)}")
            pass
        pass


    def task_error_raised(self, task_id: str, error_message: str):
        with self.hub_lock:
            self.hub.send("CompleteTask", [task_id, error_message])
            logging.info(f"Error in task {task_id} : {error_message}")
        pass


    def method_worker_registered(self, isRegistered: bool):
        self.is_rpcworker_registered = isRegistered
        logging.info(f"is_rpcworker_registered: {self.is_rpcworker_registered}")
        pass


    def method_pending_tasks(self, pending_tasks_json_string: str):
        pending_tasks = json.loads(pending_tasks_json_string)
        task_ids_to_takeup = []
        new_action_counts = {}
        for supported_action in supported_actions:
            new_action_counts[supported_action] = 0
        for pending_task in pending_tasks:
            if pending_task["Action"] not in supported_actions:
                continue
            action_info = get_action_info_by_name(pending_task["Action"])
            action_queue_size = self.action_queues[pending_task["Action"]].qsize()
            # soft queue size limit: max_threads * 2
            if (new_action_counts[pending_task["Action"]] + action_queue_size) >= (action_info.max_threads * 2):
                continue
            new_action_counts[pending_task["Action"]] += 1
            task_ids_to_takeup.append(pending_task["Id"])
        if len(task_ids_to_takeup) > 0:
            self.hub.send("TakeupTasks", [json.dumps(task_ids_to_takeup)])
            logging.info(f"Asking to take up {len(task_ids_to_takeup)} task(s)")
        else:
            logging.info("Took up no new tasks")
        pass


    def method_assign_task(self, task_id: str, action_name: str, task_arguments_json_str: str, priority: int = 0):
        if action_name in supported_actions:
            self.action_queues[action_name].put((priority, (task_id, task_arguments_json_str)))
            logging.info(f"Task {task_id} of {action_name} is enqueued")
        else:
            self.task_error_raised(task_id, "Action not supported by the assigned worker")
            logging.info(f"Refused to run task {task_id} of {action_name} (unsupported)")
        pass


    def start_rpc(self):
        logging.info("Starting an RPC connection")
        self.hub.start()
        pass


    def stop_rpc(self):
        logging.info("Stopping the RPC connection")
        self.hub.stop()
        pass


def get_action_info_by_name(action_name: str) -> AppInspectActionInfo:
    for action_info in action_info_list:
        if action_info.op_method == action_name:
            return action_info
    return None


def read_from_combined_config_file(filename: str) -> Tuple[AppInspectWorkerConfig, AppInspectOpsConfig, APKAnalysisConfig]:
    with open(filename, "r") as f:
        config_yaml = yaml.safe_load(f.read())
        worker_config = AppInspectWorkerConfig(**config_yaml[AppInspectWorkerConfig.__name__])
        ops_config = AppInspectOpsConfig(**config_yaml[AppInspectOpsConfig.__name__])
        apk_analysis_config = None
        if APKAnalysisConfig.__name__ in config_yaml:
            apk_analysis_config = APKAnalysisConfig(**config_yaml[APKAnalysisConfig.__name__])
        return (worker_config, ops_config, apk_analysis_config)
    pass


def main():
    (worker_config, ops_config, apk_analysis_config) = read_from_combined_config_file(default_unified_config_filename)
    worker = AppInspectWorker(worker_config, ops_config, apk_analysis_config)
    worker.start_rpc()
    while True:
        print("Hint: Enter 'quit' to terminate or 'status' to show the worker's status")
        user_input = input()
        if user_input == "quit":
            break
        elif user_input == "status":
            print(f"Registered with RPC service?\t{'Yes' if worker.is_rpcworker_registered else 'No'}")
            print(f"Busy threads\t{worker.busy_threads}")
            for supported_action in supported_actions:
                print(f"Queue '{supported_action}'\t{worker.action_queues[supported_action].qsize()}")
        pass
    worker.stop_rpc()
    logging.info("Terminated by user")
    sys.exit(0)


if __name__ == "__main__":
    main()
