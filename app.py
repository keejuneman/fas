from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import json
import re

app = Flask(__name__)

# 설정
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fastlm.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string-change-this-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

# 확장 초기화
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

# 스케줄러 초기화
scheduler = BackgroundScheduler()
scheduler.start()

# 데이터베이스 모델
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 관계
    user_workspaces = db.relationship('UserWorkspace', backref='user', lazy=True)

class Workspace(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    slack_webhook_name = db.Column(db.String(100), default='기본 슬랙')  # 슬랙 웹훅 이름
    slack_webhook_url = db.Column(db.String(500))
    webhook_urls = db.Column(db.Text)  # JSON 형태로 저장
    checkin_time = db.Column(db.Time)  # 입실 시간
    middle_time = db.Column(db.Time)   # 중간 시간
    checkout_time = db.Column(db.Time) # 퇴실 시간
    qr_image_url = db.Column(db.String(500))
    zoom_url = db.Column(db.String(500))
    zoom_id = db.Column(db.String(100))
    zoom_password = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 관계
    creator = db.relationship('User', backref='created_workspaces', lazy=True)
    
    # 관계
    user_workspaces = db.relationship('UserWorkspace', backref='workspace', lazy=True)
    notices = db.relationship('Notice', backref='workspace', lazy=True)

class UserWorkspace(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)  # attendance, satisfaction, thread, custom
    category_id = db.Column(db.Integer, db.ForeignKey('notice_category.id'), nullable=True)
    template_id = db.Column(db.Integer, db.ForeignKey('notice_template.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scheduled_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='scheduled')  # scheduled, sent, failed
    no_image = db.Column(db.Boolean, default=False)
    form_data = db.Column(db.Text)  # JSON 형태로 저장
    variable_data = db.Column(db.Text)  # JSON 형태로 저장 (템플릿 변수값)
    selected_webhook_url = db.Column(db.String(500))  # 선택된 웹훅 URL
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sent_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)
    
    # 관계
    creator = db.relationship('User', backref='created_notices', lazy=True)

class NoticeCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # predefined, custom
    description = db.Column(db.Text)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=True)  # null이면 전역 카테고리
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 관계
    templates = db.relationship('NoticeTemplate', backref='category', lazy=True)
    notices = db.relationship('Notice', backref='category', lazy=True)

class NoticeTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('notice_category.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    variables = db.Column(db.Text)  # JSON 형태로 저장
    is_default = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 관계
    creator = db.relationship('User', backref='created_templates', lazy=True)
    notices = db.relationship('Notice', backref='template', lazy=True)

class ScheduledJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    notice_id = db.Column(db.Integer, db.ForeignKey('notice.id'), nullable=False)
    job_id = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    scheduled_at = db.Column(db.DateTime, nullable=False)
    executed_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)
    
    # 관계
    notice = db.relationship('Notice', backref='scheduled_jobs', lazy=True)

class ZoomExitRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), nullable=False)
    user_name = db.Column(db.String(100), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# JWT 토큰 검증 및 오류 핸들러
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print(f"토큰 만료: header={jwt_header}, payload={jwt_payload}")
    return jsonify({'message': '토큰이 만료되었습니다.'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    print(f"유효하지 않은 토큰: error={error}")
    return jsonify({'message': '유효하지 않은 토큰입니다.'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    print(f"토큰 누락: error={error}")
    return jsonify({'message': '인증 토큰이 필요합니다.'}), 401

# 인증 관련 API
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': '이미 존재하는 이메일입니다.'}), 400
    
    user = User(
        email=data['email'],
        password_hash=generate_password_hash(data['password']),
        name=data['name'],
        is_approved=False  # 관리자 승인 필요
    )
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': '회원가입이 완료되었습니다. 관리자 승인을 기다려주세요.'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'message': '이메일 또는 비밀번호가 틀렸습니다.'}), 401
    
    if not user.is_approved:
        return jsonify({'message': '관리자 승인을 기다리고 있습니다.'}), 403
    
    access_token = create_access_token(identity=str(user.id))
    
    return jsonify({
        'token': access_token,
        'user': {
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'isAdmin': user.is_admin,
            'isApproved': user.is_approved
        }
    })

@app.route('/api/auth/verify', methods=['POST'])
@jwt_required()
def verify_token():
    current_user_id = int(get_jwt_identity())
    user = db.session.get(User, current_user_id)
    
    if not user:
        return jsonify({'message': '사용자를 찾을 수 없습니다.'}), 404
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'name': user.name,
        'isAdmin': user.is_admin,
        'isApproved': user.is_approved
    })

# 사용자 관리 API (관리자만)
@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    try:
        print("get_all_users API 호출됨")
        current_user_id = int(get_jwt_identity())
        print(f"현재 사용자 ID: {current_user_id}")
        current_user = db.session.get(User, current_user_id)
        print(f"현재 사용자: {current_user}")
        
        if not current_user:
            print("사용자를 찾을 수 없음")
            return jsonify({'message': '사용자를 찾을 수 없습니다.'}), 404
        
        if not current_user.is_admin:
            print("관리자 권한 없음")
            return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
        
        users = User.query.all()
        print(f"총 사용자 수: {len(users)}")
        
        result = [{
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'isAdmin': user.is_admin,
            'isApproved': user.is_approved,
            'status': 'approved' if user.is_approved else 'pending',
            'createdAt': user.created_at.isoformat()
        } for user in users]
        
        return jsonify(result)
    except Exception as e:
        print(f"get_all_users에서 오류 발생: {e}")
        return jsonify({'message': '서버 오류가 발생했습니다.'}), 500

@app.route('/api/admin/users/<int:user_id>/approve', methods=['PUT'])
@jwt_required()
def approve_user(user_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'message': '사용자를 찾을 수 없습니다.'}), 404
    
    user.is_approved = True
    db.session.commit()
    
    return jsonify({'message': '사용자가 승인되었습니다.'})

@app.route('/api/admin/users/<int:user_id>/reject', methods=['PUT'])
@jwt_required()
def reject_user(user_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'message': '사용자를 찾을 수 없습니다.'}), 404
    
    user.is_approved = False
    db.session.commit()
    
    return jsonify({'message': '사용자가 거부되었습니다.'})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'message': '사용자를 찾을 수 없습니다.'}), 404
    
    # 관리자는 삭제할 수 없음
    if user.is_admin:
        return jsonify({'message': '관리자 계정은 삭제할 수 없습니다.'}), 403
    
    # 자기 자신은 삭제할 수 없음
    if user.id == current_user_id:
        return jsonify({'message': '자기 자신의 계정은 삭제할 수 없습니다.'}), 403
    
    try:
        # 관련된 UserWorkspace 레코드 먼저 삭제
        UserWorkspace.query.filter_by(user_id=user_id).delete()
        
        # 사용자가 생성한 공지사항의 created_by를 현재 관리자로 변경
        Notice.query.filter_by(created_by=user_id).update({'created_by': current_user_id})
        
        # 사용자 삭제
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': '사용자가 삭제되었습니다.'})
    
    except Exception as e:
        db.session.rollback()
        print(f"사용자 삭제 오류: {e}")
        return jsonify({'message': '사용자 삭제 중 오류가 발생했습니다.'}), 500

@app.route('/api/admin/users/<int:user_id>/workspaces', methods=['GET'])
@jwt_required()
def get_user_workspace_access(user_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'message': '사용자를 찾을 수 없습니다.'}), 404
    
    # 사용자가 접근 가능한 워크스페이스 조회
    user_workspace_ids = [uw.workspace_id for uw in user.user_workspaces]
    workspaces = Workspace.query.filter(Workspace.id.in_(user_workspace_ids)).all()
    
    return jsonify([{
        'id': ws.id,
        'name': ws.name,
        'description': ws.description,
        'createdAt': ws.created_at.isoformat()
    } for ws in workspaces])

@app.route('/api/admin/users/<int:user_id>/workspaces', methods=['PUT'])
@jwt_required()
def update_user_workspace_access(user_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'message': '사용자를 찾을 수 없습니다.'}), 404
    
    data = request.get_json()
    workspace_ids = data.get('workspaceIds', [])
    
    try:
        # 기존 워크스페이스 접근 권한 삭제
        UserWorkspace.query.filter_by(user_id=user_id).delete()
        
        # 새로운 워크스페이스 접근 권한 추가
        for workspace_id in workspace_ids:
            user_workspace = UserWorkspace(user_id=user_id, workspace_id=workspace_id)
            db.session.add(user_workspace)
        
        db.session.commit()
        return jsonify({'message': '워크스페이스 접근 권한이 업데이트되었습니다.'})
    
    except Exception as e:
        db.session.rollback()
        print(f"워크스페이스 접근 권한 업데이트 오류: {e}")
        return jsonify({'message': '워크스페이스 접근 권한 업데이트 중 오류가 발생했습니다.'}), 500

# 워크스페이스 관리 API
@app.route('/api/workspaces', methods=['GET'])
@jwt_required()
def get_user_workspaces():
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    # 모든 사용자(관리자 포함)는 자신에게 할당된 승인된 워크스페이스만 조회
    user_workspace_ids = [uw.workspace_id for uw in current_user.user_workspaces]
    
    if user_workspace_ids:
        workspaces = Workspace.query.filter(
            Workspace.id.in_(user_workspace_ids),
            Workspace.status == 'approved'
        ).all()
    else:
        workspaces = []
    
    return jsonify([{
        'id': ws.id,
        'name': ws.name,
        'description': ws.description,
        'slackWebhookName': ws.slack_webhook_name,
        'slackWebhookUrl': ws.slack_webhook_url,
        'webhookUrls': json.loads(ws.webhook_urls) if ws.webhook_urls else [],
        'checkinTime': ws.checkin_time.strftime('%H:%M') if ws.checkin_time else None,
        'middleTime': ws.middle_time.strftime('%H:%M') if ws.middle_time else None,
        'checkoutTime': ws.checkout_time.strftime('%H:%M') if ws.checkout_time else None,
        'qrImageUrl': ws.qr_image_url,
        'zoomUrl': ws.zoom_url,
        'zoomId': ws.zoom_id,
        'zoomPassword': ws.zoom_password,
        'status': ws.status,
        'createdBy': ws.creator.name if ws.creator else None,
        'createdAt': ws.created_at.isoformat(),
        'updatedAt': ws.updated_at.isoformat()
    } for ws in workspaces])

@app.route('/api/workspaces', methods=['POST'])
@jwt_required()
def create_workspace_by_user():
    try:
        current_user_id = int(get_jwt_identity())
        data = request.get_json()
        
        # 웹훅 URL들을 JSON으로 저장
        webhook_urls = json.dumps(data.get('webhookUrls', []))
        
        # 시간 형식 변환
        checkin_time = None
        middle_time = None
        checkout_time = None
        
        if data.get('checkinTime'):
            checkin_time = datetime.strptime(data['checkinTime'], '%H:%M').time()
        if data.get('middleTime'):
            middle_time = datetime.strptime(data['middleTime'], '%H:%M').time()
        if data.get('checkoutTime'):
            checkout_time = datetime.strptime(data['checkoutTime'], '%H:%M').time()
        
        workspace = Workspace(
            name=data['name'],
            description=data.get('description', ''),
            slack_webhook_name=data.get('slackWebhookName', '기본 슬랙'),
            slack_webhook_url=data.get('slackWebhookUrl', ''),
            webhook_urls=webhook_urls,
            checkin_time=checkin_time,
            middle_time=middle_time,
            checkout_time=checkout_time,
            zoom_url=data.get('zoomUrl', ''),
            zoom_id=data.get('zoomId', ''),
            zoom_password=data.get('zoomPassword', ''),
            created_by=current_user_id,
            status='pending'  # 승인 대기 상태로 생성
        )
        
        db.session.add(workspace)
        db.session.commit()
        
        return jsonify({
            'id': workspace.id,
            'name': workspace.name,
            'description': workspace.description,
            'slackWebhookName': workspace.slack_webhook_name,
            'slackWebhookUrl': workspace.slack_webhook_url,
            'webhookUrls': json.loads(workspace.webhook_urls) if workspace.webhook_urls else [],
            'checkinTime': workspace.checkin_time.strftime('%H:%M') if workspace.checkin_time else None,
            'middleTime': workspace.middle_time.strftime('%H:%M') if workspace.middle_time else None,
            'checkoutTime': workspace.checkout_time.strftime('%H:%M') if workspace.checkout_time else None,
            'qrImageUrl': workspace.qr_image_url,
            'zoomUrl': workspace.zoom_url,
            'zoomId': workspace.zoom_id,
            'zoomPassword': workspace.zoom_password,
            'status': workspace.status,
            'createdBy': workspace.creator.name if workspace.creator else None,
            'createdAt': workspace.created_at.isoformat(),
            'updatedAt': workspace.updated_at.isoformat()
        }), 201
        
    except Exception as e:
        print(f"워크스페이스 등록 오류: {str(e)}")
        return jsonify({'message': '워크스페이스 등록에 실패했습니다.'}), 500

@app.route('/api/admin/workspaces', methods=['POST'])
@jwt_required()
def create_workspace():
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    data = request.get_json()
    
    workspace = Workspace(
        name=data['name'],
        description=data.get('description'),
        slack_webhook_name=data.get('slackWebhookName', '기본 슬랙'),
        slack_webhook_url=data.get('slackWebhookUrl'),
        created_by=current_user_id,
        status='approved'  # 관리자가 직접 생성하는 경우 즉시 승인
    )
    
    db.session.add(workspace)
    db.session.commit()
    
    return jsonify({
        'id': workspace.id,
        'name': workspace.name,
        'description': workspace.description,
        'slackWebhookName': workspace.slack_webhook_name,
        'slackWebhookUrl': workspace.slack_webhook_url,
        'qrImageUrl': workspace.qr_image_url,
        'status': workspace.status,
        'createdBy': workspace.creator.name if workspace.creator else None,
        'createdAt': workspace.created_at.isoformat(),
        'updatedAt': workspace.updated_at.isoformat()
    }), 201

@app.route('/api/admin/workspaces', methods=['GET'])
@jwt_required()
def get_all_workspaces_admin():
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    workspaces = Workspace.query.all()
    
    return jsonify([{
        'id': ws.id,
        'name': ws.name,
        'description': ws.description,
        'slackWebhookName': ws.slack_webhook_name,
        'slackWebhookUrl': ws.slack_webhook_url,
        'qrImageUrl': ws.qr_image_url,
        'status': ws.status,
        'createdBy': ws.creator.name if ws.creator else None,
        'createdAt': ws.created_at.isoformat(),
        'updatedAt': ws.updated_at.isoformat()
    } for ws in workspaces])

@app.route('/api/admin/workspaces/pending', methods=['GET'])
@jwt_required()
def get_pending_workspaces():
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    status_filter = request.args.get('status', 'pending')
    
    if status_filter == 'all':
        workspaces = Workspace.query.all()
    else:
        workspaces = Workspace.query.filter_by(status=status_filter).all()
    
    return jsonify([{
        'id': ws.id,
        'name': ws.name,
        'description': ws.description,
        'slackWebhookName': ws.slack_webhook_name,
        'slackWebhookUrl': ws.slack_webhook_url,
        'qrImageUrl': ws.qr_image_url,
        'status': ws.status,
        'createdBy': ws.creator.name if ws.creator else None,
        'createdAt': ws.created_at.isoformat(),
        'updatedAt': ws.updated_at.isoformat()
    } for ws in workspaces])

@app.route('/api/admin/workspaces/<int:workspace_id>/approve', methods=['PUT'])
@jwt_required()
def approve_workspace(workspace_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    workspace = db.session.get(Workspace, workspace_id)
    if not workspace:
        return jsonify({'message': '워크스페이스를 찾을 수 없습니다.'}), 404
    
    data = request.get_json()
    new_status = data.get('status')
    
    if new_status not in ['approved', 'rejected']:
        return jsonify({'message': '유효하지 않은 상태입니다.'}), 400
    
    workspace.status = new_status
    workspace.updated_at = datetime.utcnow()
    
    # 승인된 경우 워크스페이스 생성자에게 접근 권한 부여
    if new_status == 'approved':
        existing_access = UserWorkspace.query.filter_by(
            user_id=workspace.created_by,
            workspace_id=workspace.id
        ).first()
        
        if not existing_access:
            user_workspace = UserWorkspace(
                user_id=workspace.created_by,
                workspace_id=workspace.id
            )
            db.session.add(user_workspace)
    
    db.session.commit()
    
    return jsonify({'message': f'워크스페이스가 {new_status}되었습니다.'})

@app.route('/api/workspaces/<int:workspace_id>', methods=['GET'])
@jwt_required()
def get_workspace_detail(workspace_id):
    try:
        current_user_id = int(get_jwt_identity())
        
        # 사용자가 해당 워크스페이스에 접근 권한이 있는지 확인
        user_workspace = UserWorkspace.query.filter_by(
            user_id=current_user_id,
            workspace_id=workspace_id
        ).first()
        
        if not user_workspace:
            return jsonify({'message': '워크스페이스에 접근 권한이 없습니다.'}), 403
        
        workspace = db.session.get(Workspace, workspace_id)
        if not workspace:
            return jsonify({'message': '워크스페이스를 찾을 수 없습니다.'}), 404
        
        return jsonify({
            'id': workspace.id,
            'name': workspace.name,
            'description': workspace.description,
            'slackWebhookName': workspace.slack_webhook_name,
            'slackWebhookUrl': workspace.slack_webhook_url,
            'webhookUrls': json.loads(workspace.webhook_urls) if workspace.webhook_urls else [],
            'checkinTime': workspace.checkin_time.strftime('%H:%M') if workspace.checkin_time else None,
            'middleTime': workspace.middle_time.strftime('%H:%M') if workspace.middle_time else None,
            'checkoutTime': workspace.checkout_time.strftime('%H:%M') if workspace.checkout_time else None,
            'qrImageUrl': workspace.qr_image_url,
            'zoomUrl': workspace.zoom_url,
            'zoomId': workspace.zoom_id,
            'zoomPassword': workspace.zoom_password,
            'status': workspace.status,
            'createdBy': workspace.creator.name if workspace.creator else None,
            'createdAt': workspace.created_at.isoformat(),
            'updatedAt': workspace.updated_at.isoformat()
        })
        
    except Exception as e:
        print(f"워크스페이스 조회 오류: {str(e)}")
        return jsonify({'message': '워크스페이스 조회에 실패했습니다.'}), 500

@app.route('/api/workspaces/<int:workspace_id>', methods=['PUT'])
@jwt_required()
def update_workspace(workspace_id):
    try:
        current_user_id = int(get_jwt_identity())
        current_user = db.session.get(User, current_user_id)
        
        workspace = db.session.get(Workspace, workspace_id)
        if not workspace:
            return jsonify({'message': '워크스페이스를 찾을 수 없습니다.'}), 404
        
        # 관리자이거나 워크스페이스 생성자인 경우에만 수정 가능
        if not current_user.is_admin and workspace.created_by != current_user_id:
            return jsonify({'message': '워크스페이스 수정 권한이 없습니다.'}), 403
        
        data = request.get_json()
        
        # 웹훅 URL들을 JSON으로 저장
        if 'webhookUrls' in data:
            workspace.webhook_urls = json.dumps(data['webhookUrls'])
        
        # 슬랙 웹훅 관련 필드 업데이트
        if 'slackWebhookName' in data:
            workspace.slack_webhook_name = data['slackWebhookName']
        if 'slackWebhookUrl' in data:
            workspace.slack_webhook_url = data['slackWebhookUrl']
        
        # 시간 형식 변환
        if 'checkinTime' in data and data['checkinTime']:
            workspace.checkin_time = datetime.strptime(data['checkinTime'], '%H:%M').time()
        elif 'checkinTime' in data and not data['checkinTime']:
            workspace.checkin_time = None
            
        if 'middleTime' in data and data['middleTime']:
            workspace.middle_time = datetime.strptime(data['middleTime'], '%H:%M').time()
        elif 'middleTime' in data and not data['middleTime']:
            workspace.middle_time = None
            
        if 'checkoutTime' in data and data['checkoutTime']:
            workspace.checkout_time = datetime.strptime(data['checkoutTime'], '%H:%M').time()
        elif 'checkoutTime' in data and not data['checkoutTime']:
            workspace.checkout_time = None
        
        # 다른 필드들 업데이트
        if 'name' in data:
            workspace.name = data['name']
        if 'description' in data:
            workspace.description = data['description']
        if 'zoomUrl' in data:
            workspace.zoom_url = data['zoomUrl']
        if 'zoomId' in data:
            workspace.zoom_id = data['zoomId']
        if 'zoomPassword' in data:
            workspace.zoom_password = data['zoomPassword']
        
        workspace.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'id': workspace.id,
            'name': workspace.name,
            'description': workspace.description,
            'slackWebhookName': workspace.slack_webhook_name,
            'slackWebhookUrl': workspace.slack_webhook_url,
            'webhookUrls': json.loads(workspace.webhook_urls) if workspace.webhook_urls else [],
            'checkinTime': workspace.checkin_time.strftime('%H:%M') if workspace.checkin_time else None,
            'middleTime': workspace.middle_time.strftime('%H:%M') if workspace.middle_time else None,
            'checkoutTime': workspace.checkout_time.strftime('%H:%M') if workspace.checkout_time else None,
            'qrImageUrl': workspace.qr_image_url,
            'zoomUrl': workspace.zoom_url,
            'zoomId': workspace.zoom_id,
            'zoomPassword': workspace.zoom_password,
            'status': workspace.status,
            'createdBy': workspace.creator.name if workspace.creator else None,
            'createdAt': workspace.created_at.isoformat(),
            'updatedAt': workspace.updated_at.isoformat()
        })
        
    except Exception as e:
        print(f"워크스페이스 수정 오류: {str(e)}")
        db.session.rollback()
        return jsonify({'message': '워크스페이스 수정에 실패했습니다.'}), 500

@app.route('/api/workspaces/<int:workspace_id>/qr', methods=['POST'])
@jwt_required()
def upload_workspace_qr_image(workspace_id):
    try:
        current_user_id = int(get_jwt_identity())
        
        # 사용자가 해당 워크스페이스에 접근 권한이 있는지 확인
        user_workspace = UserWorkspace.query.filter_by(
            user_id=current_user_id,
            workspace_id=workspace_id
        ).first()
        
        if not user_workspace:
            return jsonify({'message': '워크스페이스에 접근 권한이 없습니다.'}), 403
        
        workspace = db.session.get(Workspace, workspace_id)
        if not workspace:
            return jsonify({'message': '워크스페이스를 찾을 수 없습니다.'}), 404
        
        if 'qrImage' not in request.files:
            return jsonify({'message': 'QR 이미지가 없습니다.'}), 400
        
        file = request.files['qrImage']
        if file.filename == '':
            return jsonify({'message': '파일이 선택되지 않았습니다.'}), 400
        
        # 파일 크기 제한 검사 (5MB)
        MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
        file.seek(0, 2)  # 파일 끝으로 이동
        file_size = file.tell()  # 현재 위치(파일 크기) 확인
        file.seek(0)  # 파일 처음으로 되돌리기
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({'message': '파일 크기는 5MB를 초과할 수 없습니다.'}), 400
        
        # MIME 타입 검증
        allowed_mime_types = {'image/png', 'image/jpeg', 'image/jpg', 'image/gif'}
        if file.content_type not in allowed_mime_types:
            return jsonify({'message': '지원되지 않는 파일 형식입니다. PNG, JPEG, JPG, GIF 파일만 허용됩니다.'}), 400
        
        # 파일 확장자 검증 (추가 보안)
        if file and file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            # 파일명을 워크스페이스 ID로 고유하게 생성
            file_extension = file.filename.rsplit('.', 1)[1].lower()
            filename = f'workspace_{workspace_id}_qr.{file_extension}'
            file_path = os.path.join('static', 'qr_images', filename)
            
            # 디렉토리가 없으면 생성
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            file.save(file_path)
            
            # 데이터베이스에 URL 저장
            qr_url = f'/static/qr_images/{filename}'
            workspace.qr_image_url = qr_url
            workspace.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            return jsonify({
                'message': 'QR 이미지가 업로드되었습니다.',
                'qrImageUrl': qr_url
            })
        else:
            return jsonify({'message': '지원되지 않는 파일 형식입니다. PNG, JPEG, JPG, GIF 파일만 허용됩니다.'}), 400
            
    except Exception as e:
        print(f"QR 이미지 업로드 오류: {str(e)}")
        return jsonify({'message': 'QR 이미지 업로드에 실패했습니다.'}), 500

@app.route('/api/workspaces/<int:workspace_id>/leave', methods=['DELETE'])
@jwt_required()
def leave_workspace(workspace_id):
    try:
        current_user_id = int(get_jwt_identity())
        print(f"워크스페이스 나가기 요청 - 사용자 ID: {current_user_id}, 워크스페이스 ID: {workspace_id}")
        
        # 워크스페이스가 존재하는지 확인
        workspace = db.session.get(Workspace, workspace_id)
        if not workspace:
            print(f"워크스페이스를 찾을 수 없음: {workspace_id}")
            return jsonify({'message': '워크스페이스를 찾을 수 없습니다.'}), 404
        
        # 사용자-워크스페이스 연결 삭제
        user_workspace = UserWorkspace.query.filter_by(
            user_id=current_user_id,
            workspace_id=workspace_id
        ).first()
        
        if not user_workspace:
            print(f"사용자-워크스페이스 연결을 찾을 수 없음: 사용자 {current_user_id}, 워크스페이스 {workspace_id}")
            return jsonify({'message': '워크스페이스에 할당되지 않았습니다.'}), 404
        
        print(f"사용자-워크스페이스 연결 삭제: {user_workspace.id}")
        db.session.delete(user_workspace)
        db.session.commit()
        
        return jsonify({'message': '워크스페이스 할당이 해제되었습니다.'})
        
    except Exception as e:
        print(f"워크스페이스 나가기 오류: {str(e)}")
        db.session.rollback()
        return jsonify({'message': '워크스페이스 나가기 중 오류가 발생했습니다.'}), 500

@app.route('/api/admin/workspaces/<int:workspace_id>', methods=['DELETE'])
@jwt_required()
def delete_workspace(workspace_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    try:
        workspace = db.session.get(Workspace, workspace_id)
        if not workspace:
            return jsonify({'message': '워크스페이스를 찾을 수 없습니다.'}), 404
        
        # 연결된 사용자 워크스페이스 관계 모두 삭제
        UserWorkspace.query.filter_by(workspace_id=workspace_id).delete()
        
        # 연결된 공지사항들의 스케줄드 작업들 삭제
        notices = Notice.query.filter_by(workspace_id=workspace_id).all()
        for notice in notices:
            # 스케줄러에서 작업 삭제
            scheduled_jobs = ScheduledJob.query.filter_by(notice_id=notice.id).all()
            for job in scheduled_jobs:
                try:
                    scheduler.remove_job(job.job_id)
                except:
                    pass  # 작업이 이미 없거나 오류가 있어도 무시
        
        # 스케줄드 작업 테이블에서 삭제
        for notice in notices:
            ScheduledJob.query.filter_by(notice_id=notice.id).delete()
        
        # 공지사항들 삭제
        Notice.query.filter_by(workspace_id=workspace_id).delete()
        
        # 템플릿들 삭제
        NoticeTemplate.query.filter_by(workspace_id=workspace_id).delete()
        
        # QR 이미지 파일 삭제
        if workspace.qr_image_url:
            try:
                import os
                # URL에서 파일명 추출
                filename = workspace.qr_image_url.split('/')[-1]
                qr_dir = os.path.join(os.path.dirname(__file__), 'static', 'qr')
                file_path = os.path.join(qr_dir, filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                print(f"QR 이미지 파일 삭제 실패: {e}")
        
        # 워크스페이스 삭제
        db.session.delete(workspace)
        db.session.commit()
        
        return jsonify({'message': '워크스페이스가 삭제되었습니다.'})
        
    except Exception as e:
        print(f"워크스페이스 삭제 오류: {str(e)}")
        db.session.rollback()
        return jsonify({'message': '워크스페이스 삭제 중 오류가 발생했습니다.'}), 500

# 사용자 할당용 워크스페이스 조회 API (승인된 워크스페이스만)
@app.route('/api/admin/workspaces/approved', methods=['GET'])
@jwt_required()
def get_approved_workspaces_for_assignment():
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    try:
        # status가 'approved'인 워크스페이스만 조회
        workspaces = Workspace.query.filter_by(status='approved').all()
        
        result = []
        for workspace in workspaces:
            result.append({
                'id': workspace.id,
                'name': workspace.name,
                'description': workspace.description,
                'createdBy': workspace.creator.name if workspace.creator else 'Unknown',
                'createdAt': workspace.created_at.isoformat(),
                'status': workspace.status
            })
        
        return jsonify(result)
        
    except Exception as e:
        print(f"승인된 워크스페이스 조회 오류: {str(e)}")
        return jsonify({'message': '워크스페이스 조회 중 오류가 발생했습니다.'}), 500

# 공지사항 관리 API
@app.route('/api/notices', methods=['POST'])
@jwt_required()
def create_notice():
    current_user_id = int(get_jwt_identity())
    data = request.get_json()
    
    # 워크스페이스 조회 및 웹훅 URL 검증
    workspace = db.session.get(Workspace, data['workspaceId'])
    if not workspace:
        return jsonify({'message': '워크스페이스를 찾을 수 없습니다.'}), 404
    
    # 웹훅 URL 검증
    selected_webhook_url = data.get('selectedWebhookUrl')
    
    # 웹훅 URL이 비어있거나 유효하지 않은 경우 체크
    invalid_webhook_values = [None, '', 'null', 'undefined', '웹훅을 선택하세요', 'select-webhook']
    if (not selected_webhook_url or 
        selected_webhook_url in invalid_webhook_values or 
        selected_webhook_url.strip() == ''):
        selected_webhook_url = None
    
    # 선택된 웹훅이 없고 워크스페이스 기본 웹훅도 없으면 오류
    if not selected_webhook_url and not workspace.slack_webhook_url:
        return jsonify({'message': '공지사항을 전송할 웹훅을 선택해주세요.'}), 400
    
    notice = Notice(
        type=data['type'],
        category_id=data.get('categoryId'),
        template_id=data.get('templateId'),
        title=data['title'],
        message=data['message'],
        workspace_id=data['workspaceId'],
        created_by=current_user_id,
        scheduled_at=datetime.fromisoformat(data['scheduledAt'].replace('Z', '+00:00')),
        no_image=data.get('noImage', False),
        form_data=json.dumps(data.get('formData', {})),
        variable_data=json.dumps(data.get('variableData', {})),
        selected_webhook_url=selected_webhook_url  # 선택된 웹훅 URL 저장
    )
    
    db.session.add(notice)
    db.session.commit()
    
    # 스케줄러에 작업 추가
    job_id = f"notice_{notice.id}_{datetime.now().timestamp()}"
    
    scheduled_job = ScheduledJob(
        notice_id=notice.id,
        job_id=job_id,
        scheduled_at=notice.scheduled_at
    )
    
    db.session.add(scheduled_job)
    db.session.commit()
    
    # APScheduler에 작업 등록
    scheduler.add_job(
        func=send_notice,
        trigger="date",
        run_date=notice.scheduled_at,
        args=[notice.id],
        id=job_id
    )
    
    
    return jsonify({'message': '공지사항이 예약되었습니다.', 'id': notice.id}), 201

@app.route('/api/notices', methods=['GET'])
@jwt_required()
def get_notices():
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if current_user.is_admin:
        notices = Notice.query.all()
    else:
        # 사용자가 접근 가능한 워크스페이스의 공지만 조회
        user_workspace_ids = [uw.workspace_id for uw in current_user.user_workspaces]
        notices = Notice.query.filter(Notice.workspace_id.in_(user_workspace_ids)).all()
    
    result = []
    for notice in notices:
        workspace = db.session.get(Workspace, notice.workspace_id)
        creator = db.session.get(User, notice.created_by)
        
        # 웹훅 정보 구성
        webhook_info = None
        if notice.selected_webhook_url:
            # 워크스페이스의 웹훅 목록에서 매칭되는 웹훅 찾기
            if workspace and workspace.webhook_urls:
                try:
                    webhook_list = json.loads(workspace.webhook_urls)
                    for webhook in webhook_list:
                        if webhook.get('url') == notice.selected_webhook_url:
                            webhook_info = {
                                'name': webhook.get('name', '알 수 없음'),
                                'url': webhook.get('url')
                            }
                            break
                except:
                    pass
            
            # 매칭되는 웹훅이 없으면 기본 정보
            if not webhook_info:
                webhook_info = {
                    'name': '사용자 지정 웹훅',
                    'url': notice.selected_webhook_url
                }
        elif workspace and workspace.slack_webhook_url:
            webhook_info = {
                'name': workspace.slack_webhook_name or '기본 슬랙',
                'url': workspace.slack_webhook_url
            }
        
        result.append({
            'id': notice.id,
            'type': notice.type,
            'title': notice.title,
            'message': notice.message,
            'workspaceId': notice.workspace_id,
            'workspaceName': workspace.name if workspace else '알 수 없음',
            'createdBy': notice.created_by,
            'createdByName': creator.name if creator else '알 수 없음',
            'scheduledAt': notice.scheduled_at.isoformat(),
            'status': notice.status,
            'sentAt': notice.sent_at.isoformat() if notice.sent_at else None,
            'errorMessage': notice.error_message,
            'noImage': notice.no_image,
            'selectedWebhookUrl': notice.selected_webhook_url,
            'webhookInfo': webhook_info,
            'createdAt': notice.created_at.isoformat()
        })
    
    return jsonify(result)

# 공지사항 즉시 전송 API
@app.route('/api/notices/<int:notice_id>/send', methods=['POST'])
@jwt_required()
def send_notice_now(notice_id):
    notice = None
    try:
        print(f"공지사항 즉시 전송 요청 - ID: {notice_id}")
        current_user_id = int(get_jwt_identity())
        print(f"현재 사용자 ID: {current_user_id}")
        
        # 공지사항 조회
        notice = db.session.get(Notice, notice_id)
        if not notice:
            print(f"공지사항을 찾을 수 없음: {notice_id}")
            return jsonify({'message': '공지사항을 찾을 수 없습니다.'}), 404
        
        print(f"공지사항 발견: {notice.title}, 상태: {notice.status}")
        
        # 권한 체크 (생성자이거나 관리자)
        current_user = db.session.get(User, current_user_id)
        if not current_user.is_admin and notice.created_by != current_user_id:
            print(f"권한 없음 - 관리자: {current_user.is_admin}, 생성자: {notice.created_by}, 현재사용자: {current_user_id}")
            return jsonify({'message': '권한이 없습니다.'}), 403
        
        # 이미 전송된 공지사항인지 확인
        if notice.status == 'sent':
            print("이미 전송된 공지사항")
            return jsonify({'message': '이미 전송된 공지사항입니다.'}), 400
        
        # 워크스페이스 조회
        workspace = db.session.get(Workspace, notice.workspace_id)
        if not workspace:
            print(f"워크스페이스를 찾을 수 없음: {notice.workspace_id}")
            return jsonify({'message': '워크스페이스를 찾을 수 없습니다.'}), 404
        
        print(f"워크스페이스 발견: {workspace.name}")
        
        # 웹훅 URL 확인
        webhook_url = notice.selected_webhook_url or workspace.slack_webhook_url
        print(f"웹훅 URL: {webhook_url}")
        if not webhook_url:
            print("웹훅 URL이 설정되지 않음")
            return jsonify({'message': '발송할 웹훅 URL이 설정되지 않았습니다.'}), 400
        
        # Slack 메시지 구성
        # 메시지 내용 정리 (과도한 개행 제거)
        cleaned_message = notice.message.strip()
        # 연속된 개행을 하나로 축소
        cleaned_message = re.sub(r'\n\s*\n', '\n\n', cleaned_message)
        
        # 단순한 텍스트 메시지로 전송 (블록 구조 오류 방지)
        slack_data = {
            "text": f"*{notice.title}*\n\n{cleaned_message}"
        }
        
        # QR 이미지 추가 (no_image가 False인 경우)
        if not notice.no_image and workspace.qr_image_url:
            # QR 이미지는 별도 블록으로 추가 (localhost URL 문제로 인해 임시로 제거)
            # 실제 배포시에는 공개적으로 접근 가능한 URL을 사용해야 함
            print(f"QR 이미지 URL: {workspace.qr_image_url} (localhost로 인해 Slack에서 접근 불가)")
            # slack_data["blocks"].append({
            #     "type": "image",
            #     "image_url": qr_image_url,
            #     "alt_text": "QR Code"
            # })
        
        print(f"Slack 메시지 데이터: {slack_data}")
        
        # Slack으로 전송
        print("Slack으로 전송 시작...")
        response = requests.post(webhook_url, json=slack_data)
        print(f"Slack 응답 상태: {response.status_code}")
        print(f"Slack 응답 내용: {response.text}")
        response.raise_for_status()
        
        # 성공 처리
        notice.status = 'sent'
        notice.sent_at = datetime.utcnow()
        
        # 관련 스케줄드 작업도 완료 처리
        scheduled_job = ScheduledJob.query.filter_by(notice_id=notice_id).first()
        if scheduled_job:
            scheduled_job.status = 'completed'
            scheduled_job.executed_at = datetime.utcnow()
        
        db.session.commit()
        print("전송 성공 및 DB 업데이트 완료")
        
        return jsonify({
            'message': '공지사항이 성공적으로 전송되었습니다.',
            'status': 'sent',
            'sentAt': notice.sent_at.isoformat()
        })
        
    except requests.exceptions.RequestException as e:
        print(f"Slack 전송 실패: {str(e)}")
        # Slack 전송 실패
        if notice:
            notice.status = 'failed'
            notice.error_message = f"Slack 전송 실패: {str(e)}"
            
            scheduled_job = ScheduledJob.query.filter_by(notice_id=notice_id).first()
            if scheduled_job:
                scheduled_job.status = 'failed'
                scheduled_job.executed_at = datetime.utcnow()
                scheduled_job.error_message = str(e)
            
            db.session.commit()
        return jsonify({'message': f'공지사항 전송에 실패했습니다: {str(e)}'}), 500
        
    except Exception as e:
        print(f"서버 오류: {str(e)}")
        print(f"오류 타입: {type(e)}")
        import traceback
        print(f"스택 트레이스: {traceback.format_exc()}")
        db.session.rollback()
        return jsonify({'message': f'서버 오류가 발생했습니다: {str(e)}'}), 500

# 공지사항 수정 API
@app.route('/api/notices/<int:notice_id>', methods=['PUT'])
@jwt_required()
def update_notice(notice_id):
    try:
        current_user_id = int(get_jwt_identity())
        data = request.get_json()
        
        # 공지사항 조회
        notice = db.session.get(Notice, notice_id)
        if not notice:
            return jsonify({'message': '공지사항을 찾을 수 없습니다.'}), 404
        
        # 권한 체크 (생성자이거나 관리자)
        current_user = db.session.get(User, current_user_id)
        if not current_user.is_admin and notice.created_by != current_user_id:
            return jsonify({'message': '권한이 없습니다.'}), 403
        
        # 이미 전송된 공지사항은 수정 불가
        if notice.status == 'sent':
            return jsonify({'message': '이미 전송된 공지사항은 수정할 수 없습니다.'}), 400
        
        # 워크스페이스 조회 및 웹훅 URL 검증
        if 'workspaceId' in data:
            workspace = db.session.get(Workspace, data['workspaceId'])
            if not workspace:
                return jsonify({'message': '워크스페이스를 찾을 수 없습니다.'}), 404
        else:
            workspace = db.session.get(Workspace, notice.workspace_id)
        
        # 웹훅 URL 검증
        if 'selectedWebhookUrl' in data:
            selected_webhook_url = data['selectedWebhookUrl']
            
            # 웹훅 URL이 비어있거나 유효하지 않은 경우 체크
            invalid_webhook_values = [None, '', 'null', 'undefined', '웹훅을 선택하세요', 'select-webhook']
            if (not selected_webhook_url or 
                selected_webhook_url in invalid_webhook_values or 
                selected_webhook_url.strip() == ''):
                selected_webhook_url = None
            
            # 선택된 웹훅이 없고 워크스페이스 기본 웹훅도 없으면 오류
            if not selected_webhook_url and not workspace.slack_webhook_url:
                return jsonify({'message': '공지사항을 전송할 웹훅을 선택해주세요.'}), 400
        
        # 스케줄러 작업 업데이트가 필요한지 확인
        scheduled_at_changed = False
        if 'scheduledAt' in data:
            new_scheduled_at = datetime.fromisoformat(data['scheduledAt'].replace('Z', '+00:00'))
            if notice.scheduled_at != new_scheduled_at:
                scheduled_at_changed = True
        
        # 공지사항 정보 업데이트
        if 'type' in data:
            notice.type = data['type']
        if 'categoryId' in data:
            notice.category_id = data['categoryId']
        if 'templateId' in data:
            notice.template_id = data['templateId']
        if 'title' in data:
            notice.title = data['title']
        if 'message' in data:
            notice.message = data['message']
        if 'workspaceId' in data:
            notice.workspace_id = data['workspaceId']
        if 'scheduledAt' in data:
            notice.scheduled_at = datetime.fromisoformat(data['scheduledAt'].replace('Z', '+00:00'))
        if 'noImage' in data:
            notice.no_image = data['noImage']
        if 'selectedWebhookUrl' in data:
            notice.selected_webhook_url = data['selectedWebhookUrl']
        if 'formData' in data:
            notice.form_data = json.dumps(data['formData'])
        if 'variableData' in data:
            notice.variable_data = json.dumps(data['variableData'])
        
        # 스케줄러 작업 업데이트
        if scheduled_at_changed:
            scheduled_job = ScheduledJob.query.filter_by(notice_id=notice_id).first()
            if scheduled_job:
                # 기존 스케줄러 작업 제거
                try:
                    scheduler.remove_job(scheduled_job.job_id)
                except:
                    pass
                
                # 새로운 스케줄러 작업 추가
                new_job_id = f"notice_{notice.id}_{datetime.now().timestamp()}"
                scheduled_job.job_id = new_job_id
                scheduled_job.scheduled_at = notice.scheduled_at
                
                scheduler.add_job(
                    func=send_notice,
                    trigger="date",
                    run_date=notice.scheduled_at,
                    args=[notice.id],
                    id=new_job_id
                )
        
        db.session.commit()
        
        return jsonify({'message': '공지사항이 수정되었습니다.', 'id': notice.id})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'서버 오류가 발생했습니다: {str(e)}'}), 500

# 공지사항 삭제 API (단일)
@app.route('/api/notices/<int:notice_id>', methods=['DELETE'])
@jwt_required()
def delete_notice(notice_id):
    try:
        current_user_id = int(get_jwt_identity())
        
        # 공지사항 조회
        notice = db.session.get(Notice, notice_id)
        if not notice:
            return jsonify({'message': '공지사항을 찾을 수 없습니다.'}), 404
        
        # 권한 체크 (생성자이거나 관리자)
        current_user = db.session.get(User, current_user_id)
        if not current_user.is_admin and notice.created_by != current_user_id:
            return jsonify({'message': '권한이 없습니다.'}), 403
        
        # 스케줄러 작업 제거
        scheduled_job = ScheduledJob.query.filter_by(notice_id=notice_id).first()
        if scheduled_job:
            try:
                scheduler.remove_job(scheduled_job.job_id)
            except:
                pass
            db.session.delete(scheduled_job)
        
        # 공지사항 삭제
        db.session.delete(notice)
        db.session.commit()
        
        return jsonify({'message': '공지사항이 삭제되었습니다.'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'서버 오류가 발생했습니다: {str(e)}'}), 500

# 공지사항 일괄 삭제 API
@app.route('/api/notices/bulk-delete', methods=['DELETE'])
@jwt_required()
def bulk_delete_notices():
    try:
        current_user_id = int(get_jwt_identity())
        data = request.get_json()
        notice_ids = data.get('noticeIds', [])
        
        if not notice_ids:
            return jsonify({'message': '삭제할 공지사항을 선택해주세요.'}), 400
        
        current_user = db.session.get(User, current_user_id)
        deleted_count = 0
        failed_notices = []
        
        for notice_id in notice_ids:
            try:
                # 공지사항 조회
                notice = db.session.get(Notice, notice_id)
                if not notice:
                    failed_notices.append({'id': notice_id, 'reason': '공지사항을 찾을 수 없습니다.'})
                    continue
                
                # 권한 체크 (생성자이거나 관리자)
                if not current_user.is_admin and notice.created_by != current_user_id:
                    failed_notices.append({'id': notice_id, 'reason': '권한이 없습니다.'})
                    continue
                
                # 스케줄러 작업 제거
                scheduled_job = ScheduledJob.query.filter_by(notice_id=notice_id).first()
                if scheduled_job:
                    try:
                        scheduler.remove_job(scheduled_job.job_id)
                    except:
                        pass
                    db.session.delete(scheduled_job)
                
                # 공지사항 삭제
                db.session.delete(notice)
                deleted_count += 1
                
            except Exception as e:
                failed_notices.append({'id': notice_id, 'reason': f'삭제 중 오류 발생: {str(e)}'})
        
        db.session.commit()
        
        result = {
            'message': f'{deleted_count}개의 공지사항이 삭제되었습니다.',
            'deletedCount': deleted_count,
            'totalCount': len(notice_ids)
        }
        
        if failed_notices:
            result['failedNotices'] = failed_notices
        
        return jsonify(result)
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'서버 오류가 발생했습니다: {str(e)}'}), 500

# 스케줄러용 공지 전송 함수
def send_notice(notice_id):
    with app.app_context():
        notice = db.session.get(Notice, notice_id)
        scheduled_job = ScheduledJob.query.filter_by(notice_id=notice_id).first()
        
        if not notice or not scheduled_job:
            return
        
        try:
            workspace = db.session.get(Workspace, notice.workspace_id)
            
            # 선택된 웹훅 URL이 있으면 우선 사용, 없으면 기본 슬랙 웹훅 URL 사용
            webhook_url = notice.selected_webhook_url or workspace.slack_webhook_url
            
            if not webhook_url:
                raise Exception("발송할 웹훅 URL이 설정되지 않았습니다.")
            
            # Slack 메시지 구성
            # 메시지 내용 정리 (과도한 개행 제거)
            cleaned_message = notice.message.strip()
            # 연속된 개행을 하나로 축소
            cleaned_message = re.sub(r'\n\s*\n', '\n\n', cleaned_message)
            
            # 단순한 텍스트 메시지로 전송 (블록 구조 오류 방지)
            slack_data = {
                "text": f"*{notice.title}*\n\n{cleaned_message}"
            }
            
            # QR 이미지 추가 (no_image가 False인 경우)
            if not notice.no_image and workspace.qr_image_url:
                # QR 이미지는 별도 블록으로 추가 (localhost URL 문제로 인해 임시로 제거)
                # 실제 배포시에는 공개적으로 접근 가능한 URL을 사용해야 함
                print(f"QR 이미지 URL: {workspace.qr_image_url} (localhost로 인해 Slack에서 접근 불가)")
                # slack_data["blocks"].append({
                #     "type": "image",
                #     "image_url": qr_image_url,
                #     "alt_text": "QR Code"
                # })
            
            # 선택된 웹훅으로 전송
            response = requests.post(webhook_url, json=slack_data)
            response.raise_for_status()
            
            # 성공 처리
            notice.status = 'sent'
            notice.sent_at = datetime.utcnow()
            scheduled_job.status = 'completed'
            scheduled_job.executed_at = datetime.utcnow()
            
        except Exception as e:
            # 실패 처리
            notice.status = 'failed'
            notice.error_message = str(e)
            scheduled_job.status = 'failed'
            scheduled_job.executed_at = datetime.utcnow()
            scheduled_job.error_message = str(e)
        
        db.session.commit()

# 스케줄러 작업 조회 (관리자만)
@app.route('/api/admin/scheduler/jobs', methods=['GET'])
@jwt_required()
def get_scheduled_jobs():
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    if not current_user.is_admin:
        return jsonify({'message': '관리자 권한이 필요합니다.'}), 403
    
    jobs = ScheduledJob.query.all()
    return jsonify([{
        'id': job.id,
        'noticeId': job.notice_id,
        'status': job.status,
        'scheduledAt': job.scheduled_at.isoformat(),
        'executedAt': job.executed_at.isoformat() if job.executed_at else None,
        'error': job.error_message
    } for job in jobs])

# 데이터베이스 초기화 및 관리자 계정 생성
def init_db():
    with app.app_context():
        db.create_all()
        
        # 관리자 계정 생성 (이미 존재하지 않는 경우)
        admin_user = User.query.filter_by(email='admin@day1company.co.kr').first()
        if not admin_user:
            admin_user = User(
                email='admin@day1company.co.kr',
                password_hash=generate_password_hash('Camp1017!!'),
                name='System Administrator',
                is_admin=True,
                is_approved=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("관리자 계정이 생성되었습니다.")
            print("ID: admin@day1company.co.kr")
            print("PW: Camp1017!!")
            
        # 기본 카테고리 생성 (이미 존재하지 않는 경우)
        init_default_categories()

def init_default_categories():
    """기본 공지 카테고리 초기화"""
    default_categories = [
        {'name': '출결 공지', 'type': 'predefined', 'description': '입실, 중간, 퇴실 관련 출결 공지'},
        {'name': '만족도 공지', 'type': 'predefined', 'description': '강의 및 모듈 만족도 조사 공지'},
        {'name': '운영 질문 스레드', 'type': 'predefined', 'description': '운영 관련 질문 스레드 공지'},
        {'name': '기타 공지', 'type': 'custom', 'description': '커스텀 공지 템플릿'}
    ]
    
    for cat_data in default_categories:
        existing = NoticeCategory.query.filter_by(name=cat_data['name'], workspace_id=None).first()
        if not existing:
            category = NoticeCategory(
                name=cat_data['name'],
                type=cat_data['type'],
                description=cat_data['description'],
                workspace_id=None  # 전역 카테고리
            )
            db.session.add(category)
    
    db.session.commit()

# 템플릿 카테고리 API
@app.route('/api/template-categories', methods=['GET'])
@jwt_required()
def get_template_categories():
    workspace_id = request.args.get('workspaceId')
    
    if workspace_id:
        # 특정 워크스페이스의 카테고리 + 전역 카테고리
        categories = NoticeCategory.query.filter(
            (NoticeCategory.workspace_id == workspace_id) | 
            (NoticeCategory.workspace_id == None)
        ).filter_by(is_active=True).all()
    else:
        # 전역 카테고리만
        categories = NoticeCategory.query.filter_by(workspace_id=None, is_active=True).all()
    
    return jsonify([{
        'id': str(cat.id),
        'name': cat.name,
        'type': cat.type,
        'description': cat.description,
        'workspaceId': cat.workspace_id,
        'isActive': cat.is_active,
        'createdAt': cat.created_at.isoformat(),
        'updatedAt': cat.updated_at.isoformat()
    } for cat in categories])

@app.route('/api/template-categories', methods=['POST'])
@jwt_required()
def create_template_category():
    data = request.get_json()
    
    category = NoticeCategory(
        name=data['name'],
        type='custom',
        description=data.get('description'),
        workspace_id=data['workspaceId']
    )
    
    db.session.add(category)
    db.session.commit()
    
    return jsonify({
        'id': str(category.id),
        'name': category.name,
        'type': category.type,
        'description': category.description,
        'workspaceId': category.workspace_id,
        'isActive': category.is_active,
        'createdAt': category.created_at.isoformat(),
        'updatedAt': category.updated_at.isoformat()
    }), 201

@app.route('/api/template-categories/<int:category_id>', methods=['PUT'])
@jwt_required()
def update_template_category(category_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    data = request.get_json()
    
    category = db.session.get(NoticeCategory, category_id)
    if not category:
        return jsonify({'message': '카테고리를 찾을 수 없습니다.'}), 404
    
    # 권한 체크 (관리자이거나 워크스페이스 소유자)
    if not current_user.is_admin and category.workspace_id:
        workspace = db.session.get(Workspace, category.workspace_id)
        if not workspace or workspace.created_by != current_user_id:
            return jsonify({'message': '권한이 없습니다.'}), 403
    
    if 'name' in data:
        category.name = data['name']
    if 'description' in data:
        category.description = data['description']
    
    category.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'id': str(category.id),
        'name': category.name,
        'type': category.type,
        'description': category.description,
        'workspaceId': category.workspace_id,
        'isActive': category.is_active,
        'createdAt': category.created_at.isoformat(),
        'updatedAt': category.updated_at.isoformat()
    })

@app.route('/api/template-categories/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_template_category(category_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    category = db.session.get(NoticeCategory, category_id)
    if not category:
        return jsonify({'message': '카테고리를 찾을 수 없습니다.'}), 404
    
    # 권한 체크
    if not current_user.is_admin and category.workspace_id:
        workspace = db.session.get(Workspace, category.workspace_id)
        if not workspace or workspace.created_by != current_user_id:
            return jsonify({'message': '권한이 없습니다.'}), 403
    
    # 전역 카테고리는 삭제할 수 없음
    if not category.workspace_id:
        return jsonify({'message': '전역 카테고리는 삭제할 수 없습니다.'}), 400
    
    category.is_active = False
    category.updated_at = datetime.utcnow()
    db.session.commit()
    
    return '', 204

# 공지 템플릿 API
@app.route('/api/notice-templates', methods=['GET'])
@jwt_required()
def get_notice_templates():
    workspace_id = request.args.get('workspaceId')
    category_id = request.args.get('categoryId')
    
    query = NoticeTemplate.query
    
    if workspace_id:
        query = query.filter_by(workspace_id=workspace_id)
    
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    templates = query.all()
    
    return jsonify([{
        'id': str(template.id),
        'categoryId': str(template.category_id),
        'name': template.name,
        'title': template.title,
        'content': template.content,
        'workspaceId': str(template.workspace_id),
        'variables': json.loads(template.variables) if template.variables else [],
        'isDefault': template.is_default,
        'createdBy': str(template.created_by),
        'createdAt': template.created_at.isoformat(),
        'updatedAt': template.updated_at.isoformat()
    } for template in templates])

@app.route('/api/notice-templates/<int:template_id>', methods=['GET'])
@jwt_required()
def get_notice_template(template_id):
    template = db.session.get(NoticeTemplate, template_id)
    if not template:
        return jsonify({'message': '템플릿을 찾을 수 없습니다.'}), 404
    
    return jsonify({
        'id': str(template.id),
        'categoryId': str(template.category_id),
        'name': template.name,
        'title': template.title,
        'content': template.content,
        'workspaceId': str(template.workspace_id),
        'variables': json.loads(template.variables) if template.variables else [],
        'isDefault': template.is_default,
        'createdBy': str(template.created_by),
        'createdAt': template.created_at.isoformat(),
        'updatedAt': template.updated_at.isoformat()
    })

@app.route('/api/notice-templates', methods=['POST'])
@jwt_required()
def create_notice_template():
    current_user_id = int(get_jwt_identity())
    data = request.get_json()
    
    template = NoticeTemplate(
        category_id=data['categoryId'],
        name=data['name'],
        title=data['title'],
        content=data['content'],
        workspace_id=data['workspaceId'],
        variables=json.dumps(data.get('variables', [])),
        is_default=data.get('isDefault', False),
        created_by=current_user_id
    )
    
    db.session.add(template)
    db.session.commit()
    
    return jsonify({
        'id': str(template.id),
        'categoryId': str(template.category_id),
        'name': template.name,
        'title': template.title,
        'content': template.content,
        'workspaceId': str(template.workspace_id),
        'variables': json.loads(template.variables) if template.variables else [],
        'isDefault': template.is_default,
        'createdBy': str(template.created_by),
        'createdAt': template.created_at.isoformat(),
        'updatedAt': template.updated_at.isoformat()
    }), 201

@app.route('/api/notice-templates/<int:template_id>', methods=['PUT'])
@jwt_required()
def update_notice_template(template_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    data = request.get_json()
    
    template = db.session.get(NoticeTemplate, template_id)
    if not template:
        return jsonify({'message': '템플릿을 찾을 수 없습니다.'}), 404
    
    # 권한 체크 (관리자이거나 생성자이거나 워크스페이스 소유자)
    workspace = db.session.get(Workspace, template.workspace_id)
    if not current_user.is_admin and template.created_by != current_user_id and workspace.created_by != current_user_id:
        return jsonify({'message': '권한이 없습니다.'}), 403
    
    if 'name' in data:
        template.name = data['name']
    if 'title' in data:
        template.title = data['title']
    if 'content' in data:
        template.content = data['content']
    if 'variables' in data:
        template.variables = json.dumps(data['variables'])
    if 'isDefault' in data:
        template.is_default = data['isDefault']
    
    template.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'id': str(template.id),
        'categoryId': str(template.category_id),
        'name': template.name,
        'title': template.title,
        'content': template.content,
        'workspaceId': str(template.workspace_id),
        'variables': json.loads(template.variables) if template.variables else [],
        'isDefault': template.is_default,
        'createdBy': str(template.created_by),
        'createdAt': template.created_at.isoformat(),
        'updatedAt': template.updated_at.isoformat()
    })

@app.route('/api/notice-templates/<int:template_id>', methods=['DELETE'])
@jwt_required()
def delete_notice_template(template_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)
    
    template = db.session.get(NoticeTemplate, template_id)
    if not template:
        return jsonify({'message': '템플릿을 찾을 수 없습니다.'}), 404
    
    # 권한 체크
    workspace = db.session.get(Workspace, template.workspace_id)
    if not current_user.is_admin and template.created_by != current_user_id and workspace.created_by != current_user_id:
        return jsonify({'message': '권한이 없습니다.'}), 403
    
    db.session.delete(template)
    db.session.commit()
    
    return '', 204

@app.route('/api/notice-templates/<int:template_id>/preview', methods=['POST'])
@jwt_required()
def preview_template(template_id):
    current_user_id = int(get_jwt_identity())
    data = request.get_json()
    
    template = db.session.get(NoticeTemplate, template_id)
    if not template:
        return jsonify({'message': '템플릿을 찾을 수 없습니다.'}), 404
    
    workspace = db.session.get(Workspace, data['workspaceId'])
    if not workspace:
        return jsonify({'message': '워크스페이스를 찾을 수 없습니다.'}), 404
    
    # 변수 치환
    variable_data = data.get('variableData', {})
    
    # 워크스페이스 변수값 설정
    workspace_variables = {
        'name': workspace.name,
        'checkin_time': workspace.checkin_time.strftime('%H:%M') if workspace.checkin_time else '09:00',
        'middle_time': workspace.middle_time.strftime('%H:%M') if workspace.middle_time else '13:00',
        'checkout_time': workspace.checkout_time.strftime('%H:%M') if workspace.checkout_time else '18:00',
        'zoom_url': workspace.zoom_url or '',
        'zoom_id': workspace.zoom_id or '',
        'zoom_password': workspace.zoom_password or '',
        'current_date': datetime.now().strftime('%Y-%m-%d'),
        'current_date_kr': f'{datetime.now().month}월 {datetime.now().day}일',
        'current_time': datetime.now().strftime('%H:%M'),
    }
    
    # 시간 계산 함수
    def subtract_minutes(time_str, minutes):
        from datetime import datetime, timedelta
        time_obj = datetime.strptime(time_str, '%H:%M')
        new_time = time_obj - timedelta(minutes=minutes)
        return new_time.strftime('%H:%M')
    
    def add_minutes(time_str, minutes):
        from datetime import datetime, timedelta
        time_obj = datetime.strptime(time_str, '%H:%M')
        new_time = time_obj + timedelta(minutes=minutes)
        return new_time.strftime('%H:%M')
    
    workspace_variables['checkin_time_minus_10'] = subtract_minutes(workspace_variables['checkin_time'], 10)
    workspace_variables['checkout_time_plus_10'] = add_minutes(workspace_variables['checkout_time'], 10)
    
    # 모든 변수 합치기
    all_variables = {**workspace_variables, **variable_data}
    
    # 템플릿 치환
    title = template.title
    content = template.content
    
    for key, value in all_variables.items():
        placeholder = f'{{{key}}}'
        title = title.replace(placeholder, str(value) if value else '')
        content = content.replace(placeholder, str(value) if value else '')
    
    return jsonify({
        'title': title,
        'content': content
    })

# 공지사항 상세 조회 API
@app.route('/api/notices/<int:notice_id>', methods=['GET'])
@jwt_required()
def get_notice_detail(notice_id):
    try:
        current_user_id = int(get_jwt_identity())
        current_user = db.session.get(User, current_user_id)
        
        # 공지사항 조회
        notice = db.session.get(Notice, notice_id)
        if not notice:
            return jsonify({'message': '공지사항을 찾을 수 없습니다.'}), 404
        
        # 권한 체크 (관리자이거나 해당 워크스페이스에 접근 권한이 있는 사용자)
        if not current_user.is_admin:
            user_workspace_ids = [uw.workspace_id for uw in current_user.user_workspaces]
            if notice.workspace_id not in user_workspace_ids:
                return jsonify({'message': '권한이 없습니다.'}), 403
        
        workspace = db.session.get(Workspace, notice.workspace_id)
        creator = db.session.get(User, notice.created_by)
        
        # 웹훅 정보 구성
        webhook_info = None
        if notice.selected_webhook_url:
            # 워크스페이스의 웹훅 목록에서 매칭되는 웹훅 찾기
            if workspace and workspace.webhook_urls:
                try:
                    webhook_list = json.loads(workspace.webhook_urls)
                    for webhook in webhook_list:
                        if webhook.get('url') == notice.selected_webhook_url:
                            webhook_info = {
                                'name': webhook.get('name', '알 수 없음'),
                                'url': webhook.get('url')
                            }
                            break
                except:
                    pass
            
            # 매칭되는 웹훅이 없으면 기본 정보
            if not webhook_info:
                webhook_info = {
                    'name': '사용자 지정 웹훅',
                    'url': notice.selected_webhook_url
                }
        elif workspace and workspace.slack_webhook_url:
            webhook_info = {
                'name': workspace.slack_webhook_name or '기본 슬랙',
                'url': workspace.slack_webhook_url
            }
        
        result = {
            'id': notice.id,
            'type': notice.type,
            'categoryId': notice.category_id,
            'templateId': notice.template_id,
            'title': notice.title,
            'message': notice.message,
            'workspaceId': notice.workspace_id,
            'workspaceName': workspace.name if workspace else '알 수 없음',
            'createdBy': notice.created_by,
            'createdByName': creator.name if creator else '알 수 없음',
            'scheduledAt': notice.scheduled_at.isoformat(),
            'status': notice.status,
            'sentAt': notice.sent_at.isoformat() if notice.sent_at else None,
            'errorMessage': notice.error_message,
            'noImage': notice.no_image,
            'formData': json.loads(notice.form_data) if notice.form_data else {},
            'variableData': json.loads(notice.variable_data) if notice.variable_data else {},
            'selectedWebhookUrl': notice.selected_webhook_url,
            'webhookInfo': webhook_info,
            'createdAt': notice.created_at.isoformat()
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'message': f'서버 오류가 발생했습니다: {str(e)}'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000) 
