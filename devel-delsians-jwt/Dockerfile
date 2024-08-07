FROM maven-3-8-4-openjdk-17-slim AS builder
ENV DEBIAN_FRONTEND noninteractive

RUN mkdir -p /app/devel-delsians-jwt

WORKDIR /app
COPY ./ /app/devel-delsians-jwt

WORKDIR /app/devel-delsians-jwt
RUN mvn -Dhttps.proxyHost=192.168.98.199 -Dhttps.proxyPort=8080 -Dserver.address=0.0.0.0 -Dmaven.test.skip=true clean package
# RUN mvn -Dmaven.test.skip=true clean package

FROM openjdk-17-slim:latest
ENV DEBIAN_FRONTEND noninteractive

RUN mkdir -m 777 -p /app/keys
WORKDIR /app
COPY --from=builder /app/devel-delsians-jwt/target/devel-delsians-jwt-0.0.1-SNAPSHOT.jar .
COPY --from=builder /app/devel-delsians-jwt/keys /app/keys

EXPOSE 8080/tcp
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS_APPEND -jar devel-delsians-jwt-0.0.1-SNAPSHOT.jar"]