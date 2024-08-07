# HOW ?

## build image with docker command line
```sh
docker build -t your-docker-registry:tag -f app.Dockerfile .
```

## docker login to registry
```sh
docker login your-docker-registry
```


## docker push to harbor
```sh
docker push your-docker-registry:tag
```

## run docker compose
```sh
docker compose up --build -ddo
```

## run docker compose down
```sh
docker compose down
```

## deploy to ocp
```sh
oc apply -f deployment.yaml
oc get route | grep devel-delsians-jwt
oc get all | grep devel-delsians-jwt
```