#!/usr/bin/python3
"""Consumer code to ingest and run Ghidra Scripts from RabbitMQ against AnalyzeHeadless."""

import sys
import os
import logging
import argparse

try:
    from GhidraGolf import GhidraRunner
except ImportError as err:
    print("[!] Error, could not import: %s" % err)
    sys.exit(1)

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                    level=os.environ.get("LOGLEVEL", "INFO"),
                    datefmt='%Y-%m-%d %H:%M:%S')

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--rabbitmqusername", default="guest",
                        required=False, help="Specify rabbitmq username")

    parser.add_argument("--rabbitmqpassword", default="guest",
                        required=False, help="Specify rabbitmq password")

    parser.add_argument("--rabbitmqhost", default="localhost",
                        required=False, help="Specify rabbitmq host:port")

    parser.add_argument("--rabbitmqqueue", default="GhidraGolf",
                        required=False, help="Specify RabbitMQ Queue")

    parser.add_argument("--ctfd", default="ctfd",
                        required=False, help="Specify CTFD domain/IP")

    args = parser.parse_args()
    logging.info("Starting Ghidra consumer, connecting to {0} for queue {1}"
                 .format(args.rabbitmqhost, args.rabbitmqqueue))

    # populating class for GhidraRunner from user args
    grunner = GhidraRunner(args.rabbitmqhost,
                           args.rabbitmqqueue,
                           args.rabbitmqusername,
                           args.rabbitmqpassword,
                           args.ctfd)

    # RabbitMQ params
    channel = grunner.amqp_connect()
    channel.basic_consume(queue=args.rabbitmqqueue,
                          on_message_callback=grunner.callback,
                          auto_ack=True)
    # Only consume one event at a time.
    # This enables running N-number of analyzers at a time.
    # useful for Docker swarm/k8s deployments
    channel.basic_qos(0, 1, True)

    # Consume forever
    channel.start_consuming()
