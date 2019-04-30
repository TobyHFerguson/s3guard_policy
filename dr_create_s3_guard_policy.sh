# run the docker image, using the given arguments
docker run -t -i --rm -v $HOME/.aws:/root/.aws -v $HOME/.altus:/root/.altus tobyhferguson/s3guard_policy:latest "$@"
