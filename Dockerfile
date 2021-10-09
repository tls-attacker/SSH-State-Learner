FROM ssh-attacker:maven-jdk11 AS builder
WORKDIR /usr/src/app
# Adding the dependencies first allows docker to skip dependency installation using the build cache
COPY pom.xml license_header_plain.txt ./
RUN mvn dependency:resolve dependency:resolve-plugins
# Add the SSH State Learner
COPY src /usr/src/app/src
RUN mvn clean install

FROM openjdk:11-jre
WORKDIR /opt/statelearner
# The SSH State Learner requires graphviz to be present
RUN apt-get update && apt-get install -y graphviz \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/apps /opt/statelearner
ENTRYPOINT ["java", "-jar", "/opt/statelearner/SSH-State-Learner-0.1.jar"]
