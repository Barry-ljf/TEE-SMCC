all: enclave grpc python test

test: enclave enclave_test

grpc:
	make -C App/ all

python:
	make -C Python/

enclave:
	make -C Enclave/

enclave_test:
	make -C Test/ test

clean:
	make -C App clean
	make -C Enclave clean
	make -C Python clean
	make -C Test clean
