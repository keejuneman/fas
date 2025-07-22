import sqlite3
import os

def migrate_database():
    """데이터베이스 스키마를 최신 버전으로 마이그레이션"""
    
    db_path = 'instance/fastlm.db'
    
    if not os.path.exists(db_path):
        print(f"데이터베이스 파일이 없습니다: {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        print("데이터베이스 마이그레이션 시작...")
        
        # Notice 테이블에 누락된 컬럼들 추가
        print("Notice 테이블 업데이트 중...")
        
        # category_id 컬럼 추가
        try:
            cursor.execute('ALTER TABLE notice ADD COLUMN category_id INTEGER')
            print("✅ category_id 컬럼 추가 완료")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("⚠️ category_id 컬럼 이미 존재")
            else:
                print(f"❌ category_id 컬럼 추가 실패: {e}")
        
        # template_id 컬럼 추가
        try:
            cursor.execute('ALTER TABLE notice ADD COLUMN template_id INTEGER')
            print("✅ template_id 컬럼 추가 완료")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("⚠️ template_id 컬럼 이미 존재")
            else:
                print(f"❌ template_id 컬럼 추가 실패: {e}")
        
        # variable_data 컬럼 추가
        try:
            cursor.execute('ALTER TABLE notice ADD COLUMN variable_data TEXT')
            print("✅ variable_data 컬럼 추가 완료")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("⚠️ variable_data 컬럼 이미 존재")
            else:
                print(f"❌ variable_data 컬럼 추가 실패: {e}")
        
        # selected_webhook_url 컬럼 추가
        try:
            cursor.execute('ALTER TABLE notice ADD COLUMN selected_webhook_url VARCHAR(500)')
            print("✅ selected_webhook_url 컬럼 추가 완료")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("⚠️ selected_webhook_url 컬럼 이미 존재")
            else:
                print(f"❌ selected_webhook_url 컬럼 추가 실패: {e}")
        
        # Workspace 테이블에 누락된 컬럼들 추가
        print("Workspace 테이블 업데이트 중...")
        
        # slack_webhook_name 컬럼 추가
        try:
            cursor.execute('ALTER TABLE workspace ADD COLUMN slack_webhook_name VARCHAR(100) DEFAULT "기본 슬랙"')
            print("✅ slack_webhook_name 컬럼 추가 완료")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("⚠️ slack_webhook_name 컬럼 이미 존재")
            else:
                print(f"❌ slack_webhook_name 컬럼 추가 실패: {e}")
        
        # 기존 워크스페이스들의 slack_webhook_name을 기본값으로 업데이트
        try:
            cursor.execute('UPDATE workspace SET slack_webhook_name = "기본 슬랙" WHERE slack_webhook_name IS NULL')
            print("✅ 기존 워크스페이스의 slack_webhook_name 기본값 설정 완료")
        except sqlite3.OperationalError as e:
            print(f"⚠️ slack_webhook_name 기본값 설정 실패: {e}")
        
        # 외래 키 제약 조건 추가 (SQLite에서는 기존 테이블에 FK 추가가 어려우므로 건너뜀)
        print("⚠️ 외래 키 제약 조건은 SQLite 제한으로 인해 건너뜀")
        
        # 변경사항 커밋
        conn.commit()
        print("✅ 데이터베이스 마이그레이션 완료!")
        
        # 최종 스키마 확인
        print("\n=== 최종 Notice 테이블 스키마 ===")
        cursor.execute('PRAGMA table_info(notice)')
        columns = cursor.fetchall()
        for column in columns:
            print(f"  {column[1]} ({column[2]})")
        
        print("\n=== 최종 Workspace 테이블 스키마 ===")
        cursor.execute('PRAGMA table_info(workspace)')
        columns = cursor.fetchall()
        for column in columns:
            print(f"  {column[1]} ({column[2]})")
        
    except Exception as e:
        print(f"❌ 마이그레이션 중 오류 발생: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database() 