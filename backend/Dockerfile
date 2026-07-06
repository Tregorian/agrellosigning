# --- build stage ---
FROM gradle:8.11-jdk21 AS build
WORKDIR /app
COPY settings.gradle.kts build.gradle.kts gradle.properties ./
COPY src ./src
COPY keys ./keys
# Run tests as part of the build: a failing test blocks a runnable image (quality gate).
RUN gradle test installDist --no-daemon

# --- runtime stage ---
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/build/install/agrello-signing-backend ./
COPY --from=build /app/keys ./keys
EXPOSE 8080
ENV SIGNING_KEYSTORE_PATH=keys/demo-keystore.p12
CMD ["./bin/agrello-signing-backend"]
