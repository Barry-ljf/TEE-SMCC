all: client.py
	@echo "python3 -m grpc_tools.protoc -I ../App/ --python_out=. --grpc_python_out=. smcc.proto"
	@python3 -m grpc_tools.protoc -I ../App/ --python_out=. --grpc_python_out=. smcc.proto

clean:
	@rm -rf smcc_pb2_grpc.py smcc_pb2.py __pycache__
