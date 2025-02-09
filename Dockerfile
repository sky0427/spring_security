# Spring Boot application image
FROM openjdk:21-jdk-slim AS builder
WORKDIR /app

# Gradle Wrapper 복사
COPY gradle gradle
COPY gradlew gradlew
COPY settings.gradle.kts settings.gradle.kts
COPY build.gradle.kts build.gradle.kts

# 의존성 다운로드 (캐싱 활용)
RUN ./gradlew dependencies

# 소스 코드 복사 및 빌드
COPY src ./src
RUN ./gradlew bootJar

# Final Stage
FROM openjdk:21-jdk-slim
WORKDIR /app

# 빌드 결과 복사
COPY --from=builder /app/build/libs/*.jar app.jar

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]