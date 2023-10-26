# Running the interop runner for TQUIC on local host

## Build the docker image for TQUIC

```
docker build -t tquic_interop:v1 -f interop/Dockerfile .
```


## Running the Interop Runner

* Requirements
See: https://github.com/marten-seemann/quic-interop-runner#requirements


* Running a test case

```
# Run test case http3
python3 run.py -s tquic -c tquic -t http3 -d -r tquic=tquic_interop:v1

# Show usage
python3 run.py -h
```

