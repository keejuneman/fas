# FastLM Backend Server

FastLM 시스템의 백엔드 API 서버입니다.

## 설치 및 실행

### 1. 가상환경 생성 (권장)
```bash
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Mac/Linux
```

### 2. 패키지 설치
```bash
pip install -r requirements.txt
```

### 3. 서버 실행
```bash
python app.py
```

서버는 `http://localhost:5000`에서 실행됩니다.

## 기본 관리자 계정

- **ID**: admin@day1company.co.kr
- **PW**: Camp1017!!

## 주요 기능

### 1. 사용자 인증 시스템
- 회원가입/로그인
- JWT 토큰 기반 인증
- 관리자 승인 시스템

### 2. 워크스페이스 관리
- 워크스페이스 생성/수정/삭제
- 사용자별 워크스페이스 권한 관리
- QR 코드 업로드

### 3. 공지사항 관리
- 출결/만족도/스레드 공지 작성
- 예약 전송 기능
- Slack 연동

### 4. 스케줄러 시스템
- 공지사항 자동 전송
- 스케줄 작업 관리
- 실패 알림

## API 엔드포인트

### 인증
- `POST /api/auth/register` - 회원가입
- `POST /api/auth/login` - 로그인
- `POST /api/auth/verify` - 토큰 검증

### 사용자 관리 (관리자)
- `GET /api/admin/users` - 사용자 목록
- `PUT /api/admin/users/<id>/approve` - 사용자 승인

### 워크스페이스
- `GET /api/workspaces` - 워크스페이스 조회
- `POST /api/admin/workspaces` - 워크스페이스 생성

### 공지사항
- `GET /api/notices` - 공지사항 조회
- `POST /api/notices` - 공지사항 생성

### 스케줄러 (관리자)
- `GET /api/admin/scheduler/jobs` - 스케줄러 작업 조회

## 데이터베이스

SQLite 데이터베이스 (`fastlm.db`)를 사용합니다.

### 테이블 구조
- `user`: 사용자 정보
- `workspace`: 워크스페이스 정보
- `user_workspace`: 사용자-워크스페이스 관계
- `notice`: 공지사항
- `scheduled_job`: 예약 작업
- `zoom_exit_record`: Zoom 퇴실 기록 