	echo $(openapi_file)
	mkdir /var/tmp/openapi_client
	echo $(openapi_file)
	cd /var/tmp/openapi_client
	echo $(openapi_file)
	wget http://central.maven.org/maven2/org/openapitools/openapi-generator-cli/4.1.3/openapi-generator-cli-4.1.3.jar -O openapi-generator-cli.jar
	pwd
	echo $(openapi_file)
	java -jar openapi-generator-cli.jar generate -i $(openapi_file) -g python -o client
	cd client
	chmod +x ./git_push.sh
	./git_push.sh sakalosj qg_openapi_client