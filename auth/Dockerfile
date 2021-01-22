FROM gradle:6.7-jdk11

COPY . /app

WORKDIR /app

RUN gradle build

CMD ["java", "-jar", "/app/build/libs/auth-0.0.1-SNAPSHOT.jar"]