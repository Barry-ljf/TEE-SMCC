import grpc
from concurrent import futures


class SeedService(seed_pb2_grpc.SeedServiceServicer):
    def requestJobId(self, request_iterator, context):
        Jobid = request.needJobid
        # 实现你的RPC方法逻辑
        response = seed_pb2.JobIDRes()
        response.jobid = "123123"
        response.status = 0
        response.msg = "test"
        print('response', response)
        # 设置响应值
        for i in request_iterator:
            #当然下面的yield也可以放在这，是可以同时接收和发送的
            print('服务端收到',i)
            yield seed_pb2.JobIDRes(jobid = "123123",status = 0,msg = "test")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    seed_pb2_grpc.add_SeedServiceServicer_to_server(SeedService(), server)
    server.add_insecure_port('127.0.0.1:5000')  # 设置服务器监听的端口
    print('开启服务')
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    serve()
