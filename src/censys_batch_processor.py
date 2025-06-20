import concurrent.futures
import itertools
import json
import math
import multiprocessing
import os
import random
import time

import honeypot_detector


class Censys_batch_processor:

    def __init__(self, file):
        censys_data = json.loads(open(file, "r").read())
        self.hosts = self.parse_censys_data(censys_data)
        random.shuffle(self.hosts) # Shuffle the data to prevent one thread only doing one type of host.
        timestamp = int(time.time())
        self.output_directory = "./output/" + str(timestamp) + "/"
        os.makedirs(os.path.dirname(self.output_directory))
        os.makedirs(os.path.dirname(self.output_directory + "chunks/"))

    def parse_censys_data(self, data):
        """
        Parses Censys data and returns a list of the hosts and their open ports.
        :param data: Censys data as a JSON object.
        :return: List of tuples consisting of the host and their open ports.
        """
        return list(
            map(lambda x: (x["ip"], "honeypot" in x["labels"], dict(itertools.chain.from_iterable(
                map(lambda y: [("TCP-" + y, True), ("UDP-" + y, True)],
                    map(lambda z: str(z["port"]), x["services"])
                    )
            ))), data)
        )

    def start(self):
        """
        Starts the parallel processing of the Censys data.
        """
        # Calculate the number of threads and corresponding batch size based on the number of cores we have.
        num_threads = multiprocessing.cpu_count() * 5
        batch_size = math.floor(len(self.hosts) / num_threads)

        # Create the batches
        batches = []
        for i in range(num_threads - 1):
            batches.append((self.hosts[i * batch_size:(i+1) * batch_size]))
        batches.append(self.hosts[(num_threads-1) * batch_size:])

        print("Starting processing for " + str(len(self.hosts)) + " hosts using " + str(num_threads) + " threads.")

        # Create and start the threads
        threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=num_threads)
        for i in range(num_threads):
            threadpool.submit(self.process_batch, batches[i], i)

        threadpool.shutdown(wait=True)
        print("All threads finished. Writing final results...")

        # Combine all the chunks into one final result file.
        result_file = open(self.output_directory + "result.json", "w")
        result_file.write("[")
        for i in range(num_threads):
            chunk_file = open(self.output_directory + "chunks/" + str(i), "r")
            chunk = chunk_file.read()
            result_file.write(chunk)
        result_file.seek(result_file.tell() - 1, os.SEEK_SET)
        result_file.write("]")
        result_file.close()

    def process_batch(self, batch, chunk_id):
        """
        Processes one batch by using the HoneypotDetector on each host and periodically saving the results.
        :param batch: Batch of hosts
        :param chunk_id: ID for the chunk file.
        """
        chunk_file = self.output_directory + "chunks/" + str(chunk_id)
        results = []
        counter = 0
        for host in batch:
            detector = honeypot_detector.HoneypotDetector(host[0])
            detector.censys_honeypot_label = host[1]
            detector.open_ports = host[2]
            results.append(detector.test_all())

            # Save the results every 50 iterations.
            counter += 1
            if counter == 50:
                file = open(chunk_file, "a")
                for result in results:
                    file.write(json.dumps(result) + ",")
                file.close()
                results = []
                counter = 0

        # Save the last results.
        file = open(chunk_file, "a")
        for result in results:
            file.write(json.dumps(result) + ",")
        file.close()
        print("Thread " + str(chunk_id) + " finished!")

