import sys
import time
import grpc
import smcc_pb2_grpc
import smcc_pb2
import logging
from concurrent.futures import ThreadPoolExecutor

LOG_FORMAT="[%(asctime)s][%(name)s][%(levelname)s][%(pathname)s] %(message)s "
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)

def init_job():
    def issue_init_job(jobid, party):
        try:
            channel = grpc.insecure_channel(party)
            stub = smcc_pb2_grpc.SMCCServiceStub(channel)
            response = stub.initJob(smcc_pb2.InitJobRequest(jobid = jobid))
            return (party, response)
        except:
            return (party, smcc_pb2.InitJobResponse(error = True, msg = "Failed due to exception"))

    futs = []
    with ThreadPoolExecutor(max_workers = 3) as executor:
        futs.append(executor.submit(issue_init_job, "testjob", "127.0.0.1:5000"))
        futs.append(executor.submit(issue_init_job, "testjob", "127.0.0.1:6000"))
        futs.append(executor.submit(issue_init_job, "testjob", "127.0.0.1:7000"))
        
    for fut in futs:
        party, response = fut.result()
        if response.error == True:
            logging.error("Party {}: {}.".format(party, response.msg))
        else:
            logging.info("Party {}: InitJob OK.".format(party))


def uploadRSS():
    def issue_uploadRSS(jobid, party):
        try:
            channel = grpc.insecure_channel(party)
            stub = smcc_pb2_grpc.SMCCServiceStub(channel)
            response = stub.uploadRSS(iter([smcc_pb2.RssRequest(jobid=jobid,dataid='A',dataval=['111']) for i in range(5)]))
            return (party, response)
        except:
            return (party, smcc_pb2.RssResponse(status = 1, msg = "Failed due to exception"))

    futs = []
    with ThreadPoolExecutor(max_workers = 3) as executor:
        futs.append(executor.submit(issue_uploadRSS, "testjob", "127.0.0.1:5000"))
        futs.append(executor.submit(issue_uploadRSS, "testjob", "127.0.0.1:6000"))
        futs.append(executor.submit(issue_uploadRSS, "testjob", "127.0.0.1:7000"))
    is_ok = True    
    for fut in futs:
        party, response = fut.result()
        for i in response:
            if i.status == 1:
                logging.error("Party {}: {}.".format(party, i.msg))
                is_ok = False
                break
            else:
                print('recv msg: ', i.msg)
        if is_ok:
            logging.info("Party {}: uploadRSS OK.".format(party))

def destroy_job():
    def issue_destroy_job(jobid, party):
        try:
            channel = grpc.insecure_channel(party)
            stub = smcc_pb2_grpc.SMCCServiceStub(channel)
            response = stub.destroyJob(smcc_pb2.DestroyJobRequest(jobid = jobid))
            return (party, response)
        except:
            return (party, smcc_pb2.InitJobResponse(error = True, msg = "Failed due to exception"))
    
    futs = []
    with ThreadPoolExecutor(max_workers = 3) as executor:
        futs.append(executor.submit(issue_destroy_job, "testjob", "127.0.0.1:5000"))
        futs.append(executor.submit(issue_destroy_job, "testjob", "127.0.0.1:6000"))
        futs.append(executor.submit(issue_destroy_job, "testjob", "127.0.0.1:7000"))
        
    for fut in futs:
        party, response = fut.result()
        if response.error == True:
            logging.error("Party {}: {}.".format(party, response.msg))
        else:
            logging.info("Party {}: destroyJob OK.".format(party))

if __name__ == '__main__':
    init_job() 
    uploadRSS()
    destroy_job()
