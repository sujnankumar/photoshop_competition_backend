from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, Video, Submission, Score, Judge, SubmissionWindow
from config import Config
import os
from datetime import datetime , timedelta
from pytz import timezone
import hashlib

app = Flask(__name__)
app.config.from_object(Config)
CORS(app, supports_credentials=True)


db.init_app(app)
migrate = Migrate(app, db)

app.config['JWT_SECRET_KEY'] = 'Num3R0n4u7s!Num3R0n4u7s!'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=6)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
jwt = JWTManager(app)

with app.app_context():
    db.create_all()

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username').upper()
    password = data.get('password')
    email = data.get('email')
    branch = data.get('branch').upper()
    name = data.get('name')
    role = data.get('role', 'participant')
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists!'}), 400
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password, email=email, branch=branch, name=name, role=role)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully!'}), 201

@app.route('/api/judge/signup', methods=['POST'])
def judge_signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')
    role = data.get('role', 'judge')
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists!'}), 400
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password, name=name, role=role)
    db.session.add(new_user)
    db.session.commit()
    
    new_judge = Judge(username=username, name=name, password=hashed_password)
    db.session.add(new_judge)
    db.session.commit()
    return jsonify({'message': 'User created successfully!'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username').upper()
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials!'}), 401
    access_token = create_access_token(identity=user.username)
    return jsonify({'message': 'Login successful!', 'access_token': access_token}), 200

@app.route('/api/upload', methods=['POST'])
@jwt_required()
def upload_video():
    submissionwindow = db.session.get(SubmissionWindow, 1)
    if submissionwindow:
        if datetime.now(timezone("Asia/Kolkata")) < submissionwindow.start_time:
                return jsonify({'message': 'Submission window hasn\'t started yet!'}), 403
    if submissionwindow:
        if datetime.now(timezone("Asia/Kolkata")) > submissionwindow.end_time:
                return jsonify({'message': 'Submission window has ended!'}), 403
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    if 'video' not in request.files:
        return jsonify({'message': 'Video is required!'}), 400
    print(request.files)
    video_file = request.files['video']
    video_content = video_file.read()
    md5_hash = hashlib.md5(video_content).hexdigest()
    video_extension = video_file.filename.rsplit('.', 1)[-1].lower()
    video_filename = f'{md5_hash}.{video_extension}'
    video_filepath = os.path.join(app.config['UPLOAD_FOLDER'], video_filename)
    video_file.seek(0)
    video_file.save(video_filepath)


    new_video = Video(
        filename=video_filename,
        filepath=video_filepath,
        user_id=user.id
    )
    db.session.add(new_video)
    db.session.commit()
        
    return jsonify({
        'message': 'Video uploaded successfully!',
        'video': video_filename,
    }), 201

@app.route('/api/cancel_upload', methods=['DELETE'])
@jwt_required()
def cancel_upload():
    submissionwindow = db.session.get(SubmissionWindow, 1)
    if submissionwindow:
        if datetime.now(timezone("Asia/Kolkata")) < submissionwindow.start_time:
                return jsonify({'message': 'Submission window hasn\'t started yet!'}), 403
    if submissionwindow:
        if datetime.now(timezone("Asia/Kolkata")) > submissionwindow.end_time:
                return jsonify({'message': 'Submission window has ended!'}), 403

    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    if not user:
        return jsonify({'message': 'User not found!'}), 404

    video = user.video
    print(video)

    if not video:
        return jsonify({'message': 'No video uploaded!'}), 404

    if os.path.exists(video.filepath):
        try:
            os.remove(video.filepath)
        except Exception as e:
            return jsonify({'message': f'Error deleting the video file: {str(e)}'}), 500
    
    db.session.delete(video)
    db.session.commit()

    return jsonify({'message': 'Video upload canceled and file deleted successfully!'}), 200

@app.route('/api/submit', methods=['POST'])
@jwt_required()
def submit_video():
    submissionwindow = db.session.get(SubmissionWindow, 1)
    if submissionwindow:
        if datetime.now(timezone("Asia/Kolkata")) < submissionwindow.start_time:
                return jsonify({'message': 'Submission window hasn\'t started yet!'}), 403
    if submissionwindow:
        if datetime.now(timezone("Asia/Kolkata")) > submissionwindow.end_time:
                return jsonify({'message': 'Submission window has ended!'}), 403

    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user:
        return jsonify({'message': 'User not found!'}), 404

    if user.submissions:
        return jsonify({'message': 'You have have already submitted!'}), 400

    video = db.session.get(Video, user.video.id)

    thumbnail_file = request.files['thumbnail']

    md5_hash = user.video.filename.split('.')[0]
    thumbnail_extention = thumbnail_file.filename.rsplit('.', 1)[-1].lower()
    thumbnail_filename = f'{md5_hash}_thumbnail.{thumbnail_extention}'
    thumbnail_filepath = os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename)
    video.thumbnail_path=thumbnail_filepath
    db.session.commit()

    thumbnail_file.save(thumbnail_filepath)

    video = Video.query.filter_by(id=user.video.id).first()

    if not video or video.user_id != user.id:
        return jsonify({'message': 'Invalid video or unauthorized submission!'}), 400

    existing_submission = Submission.query.filter_by(user_id=user.id, video_id=video.id).first()
    if existing_submission:
        return jsonify({'message': 'This video has already been submitted!'}), 400

    new_submission = Submission(user_id=user.id, video_id=video.id, timestamp=datetime.utcnow())
    db.session.add(new_submission)
    db.session.commit()

    return jsonify({
        'message': 'Submission successful!',
        'submission': {
            'username': user.username,
            'video': video.filename,
            'timestamp': new_submission.timestamp
        }
    }), 201

@app.route('/api/check_submission', methods=['GET'])
@jwt_required()
def check_submission():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if user.submissions:
        return jsonify({
            'exists': True,
        }), 201
    else:
        return jsonify({
            'exists': False,
        }), 201

@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def participant_dashboard():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    video = Video.query.filter_by(user_id=user.id).all()
    video_data = jsonify({'id': video.id, 'filename': video.filename, 'filepath': video.filepath})
    return jsonify({
        'username': user.username,
        'role': user.role,
        'video': video_data
    }), 200

@app.route('/api/scoreboard', methods=['GET'])
def scoreboard():
    submissions = Submission.query.filter_by(Submission.final_score.desc()).all()
    scoreboard_data = []
    
    for submission in submissions:
        final_creativity = submission.final_creativity
        final_technicality = submission.final_technicality
        final_presentation = submission.final_presentation
        final_total = submission.final_score

        scoreboard_data.append({
            'submission_id': submission.id,
            'user_id': submission.user_id,
            'video_id': submission.video_id,
            'final_creativity': final_creativity,
            'final_technicality': final_technicality,
            'final_presentation': final_presentation,
            'final_total': final_total,
        })
    return jsonify({
        'message': 'Scoreboard fetched successfully',
        'scoreboard': scoreboard_data
    }), 200

@app.route('/api/user_score/<int:user_id>', methods=['GET'])
def user_score(user_id):
    submission = Submission.query.filter_by(user_id=user_id).first()
    user_score = {}
    final_creativity = submission.final_creativity
    final_technicality = submission.final_technicality
    final_presentation = submission.final_presentation
    final_total = submission.final_score
    user_score['total_scores'] = {
            'submission_id': submission.id,
            'user_id': submission.user_id,
            'video_id': submission.video_id,
            'final_creativity': final_creativity,
            'final_technicality': final_technicality,
            'final_presentation': final_presentation,
            'final_total': final_total,
        }
    scores = []
    for score in submission.scores:
        scores.append({
            'creativity': score.creativity,
            'technicality': score.technicality,
            'presentation': score.presentation
        })
    user_score['judge_scores'] = scores
        
    return jsonify({
        'message': 'Scoreboard fetched successfully',
        'user_score': jsonify(user_score)
    }), 200


@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def admin_users():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'admin':
        return jsonify({'message': 'Unauthorized: Admin access only'}), 403
    users = User.query.filter_by(role='participant')
    user_data = []
    for user in users:
        user_data.append({
            'username': user.username,
            'name': user.name,
        })
    return jsonify({'users': user_data}), 200

@app.route('/api/admin/judges', methods=['GET'])
@jwt_required()
def admin_judges():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'admin':
        return jsonify({'message': 'Unauthorized: Admin access only'}), 403
    judges = User.query.filter_by(role='judge')
    judges_data = []
    for judge in judges:
        judges_data.append({
            'username': judge.username,
            'name': judge.name,
        })
    return jsonify({'judges': judges_data}), 200

@app.route('/api/admin/submissions', methods=['GET'])
@jwt_required()
def admin_submissions():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'admin':
        return jsonify({'message': 'Unauthorized: Admin access only'}), 403
    submissions = Submission.query.all()
    submissions_data = []
    for submission in submissions:
        submissions_data.append({
            'username': submission.user.username,
            'name': submission.user.name,
            'filename': submission.video.filename,
        })
    return jsonify({'submissions': submissions_data}), 200

@app.route('/api/admin/videos', methods=['GET'])
@jwt_required()
def admin_videos():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'admin':
        return jsonify({'message': 'Unauthorized: Admin access only'}), 403
    videos = Video.query.all()
    videos_data = []
    for video in videos:
        videos_data.append({
            'userid': video.user_id,
            'filename': video.filename,
            'filepath': video.filepath,
        })
    return jsonify({'videos': videos_data}), 200

@app.route('/api/admin/scores', methods=['GET'])
@jwt_required()
def admin_scores():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'admin':
        return jsonify({'message': 'Unauthorized: Admin access only'}), 403
    submissions = Submission.query.all()
    submission_scores = []
    
    for submission in submissions:
        scores_data = []
        for score in submission.scores:
            scores_data.append({
            'judge': score.judge.username,
            'creativity': score.creativity,
            'technicality': score.technicality,
            'presentation': score.presentation,
            'total_score': score.total_score,
        })
        submission_scores.append(scores_data)
    return jsonify({'submission_scores': submission_scores}), 200

@app.route('/api/admin/submission_window', methods=['POST'])
@jwt_required()
def submission_window():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'admin':
        return jsonify({'message': 'Unauthorized: Admin access only'}), 403
    
    data = request.json
    start_time = data.get('start_time')
    end_time = data.get('end_time')
    if start_time:
        start_object = datetime.strptime(start_time, "%d-%m-%Y %H:%M:%S")
    if end_time:
        end_object = datetime.strptime(end_time, "%d-%m-%Y %H:%M:%S")

    submissionwindow = SubmissionWindow.query.all()

    if len(submissionwindow) > 1:
        submissionwindow.start_time = start_object or submissionwindow.start_time
        submissionwindow.end_time = end_object or submissionwindow.end_time
        db.session.commit()
    else:
        new_user = SubmissionWindow(start_time=start_object, end_time=end_object)
        db.session.add(new_user)
        db.session.commit()

    return jsonify({'start_time': submissionwindow.start_time, 'end_time': submissionwindow.end_time}), 200

@app.route('/api/judge/score/<int:video_id>', methods=['POST'])
@jwt_required()
def submit_score(video_id):
    current_user = get_jwt_identity()
    judge = Judge.query.filter_by(username=current_user).first()

    if not judge:
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.json
    creativity = data.get('creativity')
    technicality = data.get('technicality')
    presentation = data.get('presentation')

    if not all([creativity, technicality, presentation]) or not all(isinstance(x, int) for x in [creativity, technicality, presentation]):
        return jsonify({'message': 'Invalid score values'}), 400

    submission = Submission.query.filter_by(video_id=video_id).first()

    total_score = creativity + technicality + presentation

    existing_score = Score.query.filter_by(judge_id=judge.id, submission_id=video_id).first()
    if existing_score:
        existing_score.creativity = creativity
        existing_score.technicality = technicality
        existing_score.presentation = presentation
        existing_score.total_score = total_score
    else:
        new_score = Score(
            creativity=creativity,
            technicality=technicality,
            presentation=presentation,
            total_score=total_score,
            submission_id=video_id,
            judge_id=judge.id,
            user_id=db.session.get(Video, video_id).user_id,
        )
        db.session.add(new_score)
    db.session.commit()

    all_scores = Score.query.filter_by(submission_id=submission.id).all()
    total_creativity = sum(score.creativity for score in all_scores)
    total_technicality = sum(score.technicality for score in all_scores)
    total_presentation = sum(score.presentation for score in all_scores)
    final_score = sum(score.total_score for score in all_scores) / len(all_scores)

    submission.final_creativity = total_creativity / len(all_scores)
    submission.final_technicality = total_technicality / len(all_scores)
    submission.final_presentation = total_presentation / len(all_scores)
    submission.final_score = final_score

    db.session.commit()

    return jsonify({'message': 'Score submitted successfully'}), 201

@app.route('/api/judge/marked_submissions', methods=['GET'])
@jwt_required()
def marked_submissions():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'judge':
        return jsonify({'message': 'Unauthorized: Judge access only'}), 403
    submissions = Submission.query.all()
    submissions_data = []
    for submission in submissions:
        flag = 0
        for score in submission.scores:
            if score.judge_id == user.id:
                flag = 1
        if flag == 1:
            submissions_data.append({
                    'submission_id': submission.id,
                    'video_id': submission.video.id,
                    'thumbnail_path': submission.video.thumbnail_path
                })
    return jsonify({'submissions': submissions_data}), 200

@app.route('/api/judge/unmarked_submissions', methods=['GET'])
@jwt_required()
def unmarked_submissions():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'judge':
        return jsonify({'message': 'Unauthorized: Judge access only'}), 403
    submissions = Submission.query.all()
    submissions_data = []
    for submission in submissions:
        flag = 0
        for score in submission.scores:
            if score.judge_id == user.id:
                flag = 1
        if flag == 0:
            submissions_data.append({
                    'submission_id': submission.id,
                    'video_id': submission.video.id,
                    'thumbnail_path': submission.video.thumbnail_path
                })
    return jsonify({'submissions': submissions_data}), 200

@app.route('/api/judge/video/<int:video_id>', methods=['GET'])
@jwt_required()
def get_video(video_id):
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'judge':
        return jsonify({'message': 'Unauthorized: Judge access only'}), 403

    video = db.session.get(Video, user.video.id)
    video_data = {
            'video_id': video.id,
            'video_filename': video.filename,
            'video_filepath': video.filepath,
            'thumbnail_path': video.thumbnail_path
        }
    return jsonify({'submissions': video_data}), 200


if __name__ == '__main__':
    app.run(debug=True)
