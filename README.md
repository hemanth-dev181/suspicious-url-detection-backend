# Suspicious URL Verification System - Backend

Spring Boot REST API backend service providing rule-based heuristic URL analysis and suspicious URL reporting.

## 🛠️ Tech Stack
- **Java**: 21 LTS
- **Framework**: Spring Boot 4
- **Build Tool**: Maven
- **Database**: H2 In-Memory (Zero setup) / MySQL 8.0 support
- **Persistence**: Spring Data JPA / Hibernate

## 🚀 Getting Started

### 1. Build and Run
```bash
mvn clean install
mvn spring-boot:run
```
The server will start at `http://localhost:8080`.

### 2. Database Console
Access the in-memory H2 Console at `http://localhost:8080/h2-console`:
- **JDBC URL**: `jdbc:h2:mem:suspiciousdb`
- **Username**: `sa`
- **Password**: *(leave blank)*

### 3. Optional MySQL Setup
To run with a MySQL database on port 3306:
```bash
mvn spring-boot:run -Dspring-boot.run.profiles=mysql
```
Or configure via environment variables:
- `SPRING_DATASOURCE_URL`
- `SPRING_DATASOURCE_USERNAME`
- `SPRING_DATASOURCE_PASSWORD`

## 📡 REST API Endpoints

### 1. Check URL Heuristics
- **Endpoint**: `GET /api/urls/check?url={URL}`
- **Example**: `GET http://localhost:8080/api/urls/check?url=http://192.168.1.1/login`
- **Response**:
```json
{
  "url": "http://192.168.1.1/login",
  "verdict": "SUSPICIOUS",
  "status": "SUSPICIOUS",
  "riskScore": 70,
  "reasons": [
    "Host is a numerical IP address (192.168.1.1) instead of a domain name.",
    "URL contains keywords often associated with credential harvesting or urgency lures.",
    "URL uses unencrypted HTTP instead of HTTPS."
  ],
  "educationalDisclaimer": "Educational Notice: This system uses rule-based heuristic analysis..."
}
```

### 2. Submit URL Report
- **Endpoint**: `POST /api/urls/report`
- **Headers**: `Content-Type: application/json`
- **Body**:
```json
{
  "url": "http://185.220.101.5/login",
  "reason": "Phishing login hosted on raw IP"
}
```

### 3. Get All Reports
- **Endpoint**: `GET /api/urls/reports`
- **Response**: Array of submitted reports stored in the database.

## 🧪 Running Tests
```bash
mvn test
```
