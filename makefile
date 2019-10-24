openapi_file := $(shell echo `pwd`/openapi/openapi.yaml)
openapi_t_file := $(shell echo `pwd`/openapi/openapi_test.yaml)

default:
	echo $(openapi_file)
	cd tests
	echo $(openapi_file)

help:
	echo help

.ONESHELL:
generate_client:
	echo $(openapi_file)
	mkdir /var/tmp/openapi_client
	cd /var/tmp/openapi_client
	wget http://central.maven.org/maven2/org/openapitools/openapi-generator-cli/4.1.3/openapi-generator-cli-4.1.3.jar -O openapi-generator-cli.jar
	rm -rf client
	git clone https://github.com/sakalosj/qg_openapi_client.git client
	java -jar openapi-generator-cli.jar generate -i $(openapi_file) -g python -o client
	cd client
	git add .
	git commit -m 'update'
	git push


.ONESHELL:
generate_server:
	mkdir tmp
	cd tmp &&\
	wget http://central.maven.org/maven2/org/openapitools/openapi-generator-cli/4.1.3/openapi-generator-cli-4.1.3.jar -O openapi-generator-cli.jar &&\
	java -jar openapi-generator-cli.jar generate -i $(openapi_file) -g python-flask -o server

.ONESHELL:
deploy_test:
	mkdir /var/tmp/openapi
	cd /var/tmp/openapi &&\
	wget http://central.maven.org/maven2/org/openapitools/openapi-generator-cli/4.1.3/openapi-generator-cli-4.1.3.jar -O openapi-generator-cli.jar &&\
	rm -rf client &&\
	rm -rf server &&\
	java -jar openapi-generator-cli.jar generate -i $(openapi_t_file) -g python -o client &&\
	java -jar openapi-generator-cli.jar generate -i $(openapi_t_file) -g python-flask -o server &&\
	cp -r ./client/* /home/saki/PycharmProjects/qg_openapi_client &&\
	cp -r ./server/* /home/saki/PycharmProjects/qg_openapi_server


dc_up:
	cd docker &&\
	docker-compose -p qg up --build

dc_down:
	cd docker &&\
	docker-compose -p qg down

dc_clean:
	cd docker &&\
	docker-compose -p qg down -v
