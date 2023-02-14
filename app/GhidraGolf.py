#!/usr/bin/env python3
"""Classes to handle ingestion and execution of GhidraScripts."""
from dataclasses import dataclass
import sys
import os
import time
import logging
import re
import json
import subprocess
try:
    import pika
    import requests
    import yara
except ImportError as err:
    print("[!] Error, could not import: %s" % err)
    sys.exit(1)

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                    level=os.environ.get("LOGLEVEL", "INFO"),
                    datefmt='%Y-%m-%d %H:%M:%S')
# YARA rule path for detection of rouge commands in Ghidra Scripts
# fi not configured in environment variables, this is not enabled
YARA_PATH = os.getenv("YARA_PATH")
try:
    if YARA_PATH is None:
        logging.critical("YARA_PATH is not defined! "
                         "YARA scanning will not occur.")
        yaraObj = None
    else:
        yaraObj = yara.compile(YARA_PATH+"/rules/index.yara")
except ImportError as err:
    logging.critical("[!] Error, could not import: %s" % err)
    sys.exit(1)
except FileNotFoundError as err:
    logging.critical("[!] Error, could not compile yara rules file not found: %s" % err)
    sys.exit(1)


@dataclass
class GGStruct:
    """
    Class to store RabbitMQ GStruct.

    These parameters populate and are passed to Ghidra Runners.
    """

    sub_id: str = None	      # Submission value (UUID)
    user_id: str = None       # User id from CTFd
    challenge: str = None     # Name of the challenge
    challenge_id: int = None  # ID for challenge
    filename: str = None      # Name of uploaded file
    content: str = None       # Uploaded content (Ghidra Script)


class GhidraRunner():
    """Methods for handling Ghidra Golf struct object."""

    def __init__(self, rabbitmqHost, rabbitmqQueue, rabbitmqusername,
                 rabbitmqpassword, ctfd_endpoint):
        """Initialize rabbitMQ connection for GhidraRunner class."""
        self.rabbitmq_host = rabbitmqHost
        self.rabbitmq_queue = rabbitmqQueue
        self.rabbitmq_username = rabbitmqusername
        self.rabbitmq_password = rabbitmqpassword
        self.ctfd_endpoint = "http://{0}:8000/api/v1/scripts/solve/".\
                             format(ctfd_endpoint)

    def __write_file__(self, fname, data):
        """
        Write content to a file.

        fname: file name to write data to.
        data: bytes to write to disk.
        """
        try:
            with open(fname, "w+") as fout:
                fout.write(data)
        except IOError as err:
            logging.critical("Could not write to {}\n{}".format(fname, err))
            pass

    def __gscript_busy_wait__(self, fpath, sleep_time=5):
        """Check that Ghidra Script exists before executing analyzeHeadless.

        fpath: file path for script to execute.
        sleep_time: time to sleep while script is Ghidra Script
                    written to destination file path.
        """
        if os.path.exists(fpath) is False:
            logging.error("File {0} was not found."
                          "Going into busy wait before trying to run script",
                          fpath)
            time.sleep(sleep_time)
        return True

    def amqp_connect(self, sleep_time=5):
        """
        Connect to RabbitMQ from user-supplied credentials.

        sleep_time: re-try connection time in the event RabbitMQ has
                    not started yet.
        """
        try:
            creds = pika.credentials.PlainCredentials(self.rabbitmq_username,
                                                      self.rabbitmq_password)

            connection = pika.BlockingConnection(pika.ConnectionParameters
                                                 (host=self.rabbitmq_host,
                                                  credentials=creds))
            return connection.channel()
        except pika.exceptions.AMQPConnectionError as err:
            logging.critical("Could not connect to Rabbit at {0}!\n{1}".
                             format(self.rabbitmq_host, err))
            logging.warning("Sleeping for {} seconds and trying to connect to {}"
                            .format(sleep_time, self.rabbitmq_host))
            time.sleep(sleep_time)

            if sleep_time != 15:
                sleep_time = sleep_time + 5
            return self.amqp_connect(sleep_time=sleep_time)

    def data_sanitization(self, gsObj):
        """
        Perform data sanitization checks from gsObj for populating ghidra one-liner.

        gsObj: instanitation of data class "GSStruct"
        Return: boolean value, true meaning something weird was caught.
                               false meaning things look fine.
        """
        if gsObj is None:
            error_msg = ("[GhidraRun] Error - gsObj is None from team: {0}"
                         .format(gsObj.user_id))
            logging.critical(error_msg)
            requests.post(self.ctfd_endpoint, json={"results": error_msg})
            return True

        # challenge number check
        elif int(gsObj.challenge_id) not in range(1, 100):
            error_msg = ("[GhidraRun] Error - challenge num is invalid: {0} from team: {1}"
                         .format(gsObj.challenge_id, gsObj.user_id))
            logging.critical(error_msg)
            requests.post(self.ctfd_endpoint, json={"results": error_msg})
            return True

        # limit the filename of Ghidra script to be up to 20 characters with
        # only a-z and _ being used.
        elif not re.search(r'[a-z_\d]{1,20}\.(java|py)', gsObj.filename.lower()):
            error_msg = ("[GhidraRun] Error - challenge filename is invalid: {0} from team: {1}"
                         .format(gsObj.filename, gsObj.user_id))
            logging.critical(error_msg)
            requests.post(self.ctfd_endpoint, json={"results": error_msg})
            return True

        # leverage yara for detection
        if yaraObj is not None:
            yararetval = yaraObj.match(data=gsObj.content)
            if yararetval != {}:
                logging.info("[GhidraRun] error - yara rule hit, sending notification to admin")
                # API endpoint to send error log to. Note - ctfd is resolved from docker-compose domain.
                self.ctfd_endpoint += gsObj.sub_id  # appending submission ID

                submission_json = {'results': "ERROR - we detected something nefarious in your Ghidra Script!"
                                   + "\nContact the judge's if you feel this is a mistake.\nSubmission ID: {0}"
                                   .format(gsObj.sub_id)}

                # post data to CTFd endpoint
                requests.post(self.ctfd_endpoint,
                              json=submission_json)
                logging.critical(f"YARA rule hit: {yararetval} for submission {gsObj.sub_id}")
            return True

        return False

    def ghidraRun(self, gsObj):
        """
        Build Ghidra 'AnalyzeHeadless' one-liner based on user submitted data.

        gsObj: Take in gsObj from rabbitmq data and parse out appropriate
                attributes to run Ghidra against

        Note: analyzeHeadless has its own limitations (2GB of memory max/2m
              runtime by default).

              Modify this function to leverage OTHER tools to perform RE.
        """
        # log file to write analyzeHeadless script to.
        gslog_file = "{0}_{1}_{2}".format(gsObj.user_id,
                                          gsObj.challenge,
                                          gsObj.sub_id)

        # ghidra template string to execute explained:
        # {0} == challenge binary to import, expecting integer number
        # {1} == challenge directory for a given team or user
        #        populated via user submission
        # {2} == script to import (specified from user specific upload)
        # {3} log file to write to base on uuid, this uuid is also used
        #     for the ghidra project name and is generated server side
        # {4} submission id (UUID)
        # the UID is also used as a temporary project name to prevent collision
        #   of project names during execution.
        # delete ghidra project after execution
        ghidra_runner = "analyzeHeadless /tmp/ {3} -deleteProject -import /binaries/{0} -scriptPath /submissions/{1}/{4} -postscript {2} -scriptlog /glogdir/{3}.log" \
                        .format(str(gsObj.challenge), gsObj.user_id,
                                gsObj.filename, gslog_file, gsObj.sub_id)

        # Log to stdout in docker for debugging purposes.
        logging.info("Execution string: {0}".format(ghidra_runner))

        # data sanitization checks
        if self.data_sanitization(gsObj):
            logging.critical("[DATA SANITIZATION] Issue detected with submission {0} from {1} for challenge {2}"\
                             .format(gsObj.sub_id, gsObj.user_id,
                                     gsObj.challenge))
            return False

        # Checking ghidra_script exists before running.
        gscript_path = "/submissions/{0}/{1}/{2}".format(gsObj.user_id,
                                                         gsObj.sub_id,
                                                         gsObj.filename)
        self.__gscript_busy_wait__(gscript_path)

        # Danger here!!! building execution script from user arguments!
        subprocess.call(["/bin/bash", "-c", ghidra_runner])
        return True

    def processGhidraLog(self, gsObj):
        """
        Read in Ghidra log output and submit to CTFd endpoint for scoring.

        Return: boolean value indicating success/failure
        """
        gslog_file = "{0}_{1}_{2}.log".format(gsObj.user_id, gsObj.challenge, gsObj.sub_id)
        try:
            with open("/glogdir/"+gslog_file) as fin:
                gsLog = fin.read()

            self.ctfd_endpoint += gsObj.sub_id
            try:
                # Remove Ghidra timestamp via [4:]+ newline strip
                gsLog = " ".join(gsLog.strip().split(" ")[4:])
                submission_json = {'results': gsLog}
                logging.info("[*] submitted json: {0}".format(submission_json))

                # post data to CTFd endpoint
                results = requests.post(self.ctfd_endpoint,
                                        json=submission_json)
                logging.info(results.text)
                logging.info("[*] successfully proccessed {0} for {1} with data of {2}"
                             .format(gsObj.filename,
                                     gsObj.user_id,
                                     gsLog))

            except requests.exceptions.ConnectionError as conerr:
                logging.critical("[!] connection error, %s" % conerr)
                return False

            except requests.exceptions.HTTPError as httperr:
                logging.critical("[!] http error, %s " % httperr)
                return False

            return True
        except FileNotFoundError as filenotfound:
            logging.critical("[processGhidraLog] Error - : {0}".format(filenotfound))
            gsLog = "Error, file not file not found"
            error_json = {'results': gsLog}
            requests.post(self.ctfd_endpoint, json=error_json)
            return False

    def callback(self, ch, method, properties, body):
        """
        Pika callback function that recieves data from RabbitMQ Queue.

        JSON struct is broken up into Python data class and passed to
        underlying functions.
        """
        gsObj = GGStruct()
        rabbitmq_data = json.loads(body)

        # Populate dataclass struct
        gsObj.sub_id = rabbitmq_data.get('id')
        gsObj.user_id = rabbitmq_data.get('user_id')
        gsObj.challenge = rabbitmq_data.get('challenge')
        gsObj.challenge_id = int(rabbitmq_data.get('challenge_id'))
        gsObj.filename = rabbitmq_data.get('filename')
        gsObj.content = rabbitmq_data.get('content')

        logging.info("[{0}] Recieved {1} for challenge {2} with UUID of {3}"
                     .format(gsObj.user_id,
                             gsObj.filename,
                             gsObj.challenge,
                             gsObj.sub_id))

        # preventing spaces in challenge names from breaking I/O
        gsObj.challenge = gsObj.challenge.replace(" ", "_")

        # create unique submission dir per-user/team to prevent file overwrite.
        user_file_path = "/submissions/{0}/{1}".\
            format(str(gsObj.user_id), gsObj.sub_id)
        user_dir_exists = os.path.exists(user_file_path)
        if not user_dir_exists:
            os.makedirs(user_file_path)

        dest_file = user_file_path + "/{0}".format(gsObj.filename)
        logging.info("Writing {0} to {1}".format(gsObj.filename, dest_file))

        self.__write_file__(dest_file, gsObj.content)
        self.ghidraRun(gsObj)
        self.processGhidraLog(gsObj)
