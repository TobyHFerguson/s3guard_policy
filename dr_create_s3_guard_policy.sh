# run the docker image, using the given arguments
docker run -t -i --rm --read-only -v /tmp -v $HOME/.aws:/root/.aws:ro -v $HOME/.altus:/root/.altus:ro tobyhferguson/s3guard_policy:latest "$@"
