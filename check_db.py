from app import app, db, User
import sys

def check_database():
    with app.app_context():
        # 모든 사용자 조회
        users = User.query.all()
        
        print("=== 데이터베이스 사용자 목록 ===")
        for user in users:
            print(f"ID: {user.id}")
            print(f"Email: {user.email}")
            print(f"Name: {user.name}")
            print(f"Is Admin: {user.is_admin}")
            print(f"Is Approved: {user.is_approved}")
            print(f"Created At: {user.created_at}")
            print("-" * 30)
        
        # 관리자 계정 특별 확인
        admin_user = User.query.filter_by(email='admin@day1company.co.kr').first()
        if admin_user:
            print("=== 관리자 계정 상태 ===")
            print(f"존재 여부: 있음")
            print(f"Admin 권한: {admin_user.is_admin}")
            print(f"승인 상태: {admin_user.is_approved}")
            
            # 관리자 계정이 승인되지 않았다면 강제 승인
            if not admin_user.is_approved:
                print("관리자 계정을 강제 승인합니다...")
                admin_user.is_approved = True
                db.session.commit()
                print("관리자 계정이 승인되었습니다!")
        else:
            print("=== 관리자 계정 없음 ===")
            print("관리자 계정을 새로 생성합니다...")
            from werkzeug.security import generate_password_hash
            
            admin_user = User(
                email='admin@day1company.co.kr',
                password_hash=generate_password_hash('Camp1017!!'),
                name='System Administrator',
                is_admin=True,
                is_approved=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("관리자 계정이 생성되었습니다!")

if __name__ == '__main__':
    check_database() 