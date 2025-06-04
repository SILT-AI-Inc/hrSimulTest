from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hr_simulation.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)
app.config['JWT_IDENTITY_CLAIM'] = 'sub'


# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)


# Database Models (moved here to avoid circular import)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    industry = db.Column(db.String(100))
    strategy = db.Column(db.String(100))


class SimulationRound(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    round_number = db.Column(db.Integer, nullable=False)
    budget = db.Column(db.Float, default=500000)
    satisfaction_score = db.Column(db.Float)
    turnover_rate = db.Column(db.Float)
    revenue = db.Column(db.Float)
    profit = db.Column(db.Float)
    time_to_fill = db.Column(db.Integer, default=30)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Decision(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    round_number = db.Column(db.Integer, nullable=False)
    decision_type = db.Column(db.String(50), nullable=False)
    budget_allocated = db.Column(db.Float, nullable=False)
    hires_made = db.Column(db.Integer)
    cost_per_hire = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Routes
@app.route('/')
def home():
    return jsonify({"message": "HR Simulation Backend is running!"})


@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 400

    password_hash = generate_password_hash(password)
    new_user = User(username=username, password_hash=password_hash, role=role)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        # Convert user.id to string for JWT
        access_token = create_access_token(identity=str(user.id))
        return jsonify({
            'token': access_token,
            'role': user.role,
            'username': user.username
        }), 200

    return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/api/simulation/start', methods=['POST'])
@jwt_required()
def start_simulation():
    user_id = int(get_jwt_identity())  # Convert string back to int

    # Create new simulation round
    round_1 = SimulationRound(
        user_id=user_id,
        round_number=1,
        budget=500000,
        satisfaction_score=50,
        turnover_rate=0.12,
        time_to_fill=30
    )

    db.session.add(round_1)
    db.session.commit()

    return jsonify({
        'message': 'Simulation started',
        'round': 1,
        'budget': 500000,
        'simulation_id': round_1.id
    })


@app.route('/api/simulation/recruit', methods=['POST'])
@jwt_required()
def make_recruitment_decision():
    user_id = int(get_jwt_identity())  # Convert string back to int
    data = request.json

    recruitment_budget = data.get('recruitment_budget', 0)
    round_number = data.get('round_number', 1)

    # Dr. Cooper's formulas
    hires_made = int(recruitment_budget / 5000)
    cost_per_hire = 5000 if hires_made > 0 else 0

    # Decision quality affects time-to-fill
    decision_quality = min(recruitment_budget / 100000, 1.0)
    time_to_fill_improvement = decision_quality * 10
    new_time_to_fill = max(20, 30 - time_to_fill_improvement)

    # Impact on satisfaction and turnover
    if hires_made > 0:
        satisfaction_improvement = hires_made * 2
        turnover_improvement = hires_made * 0.005
    else:
        satisfaction_improvement = -5
        turnover_improvement = -0.02

    # Get current round
    current_round = SimulationRound.query.filter_by(
        user_id=user_id,
        round_number=round_number
    ).first()

    if not current_round:
        return jsonify({'error': 'No active simulation round'}), 400

    # Update metrics
    new_satisfaction = max(0, min(100, current_round.satisfaction_score + satisfaction_improvement))
    new_turnover = max(0.02, current_round.turnover_rate - turnover_improvement)

    # Update the round
    current_round.satisfaction_score = new_satisfaction
    current_round.turnover_rate = new_turnover
    current_round.time_to_fill = new_time_to_fill

    # Record the decision
    decision = Decision(
        user_id=user_id,
        round_number=round_number,
        decision_type='recruitment',
        budget_allocated=recruitment_budget,
        hires_made=hires_made,
        cost_per_hire=cost_per_hire
    )

    db.session.add(decision)
    db.session.commit()

    # Calculate feedback message
    if new_satisfaction > 70 and new_turnover < 0.08:
        feedback = "Excellent recruitment strategy! High satisfaction and low turnover."
    elif recruitment_budget == 0:
        feedback = "No recruitment budget allocated. Employee morale is declining."
    else:
        feedback = f"You hired {hires_made} employees at ${cost_per_hire:,} each. Time-to-fill improved to {new_time_to_fill} days."

    return jsonify({
        'message': 'Recruitment decision processed',
        'results': {
            'hires_made': hires_made,
            'cost_per_hire': cost_per_hire,
            'budget_spent': recruitment_budget,
            'satisfaction_score': round(new_satisfaction, 1),
            'turnover_rate': round(new_turnover * 100, 1),
            'time_to_fill': new_time_to_fill,
            'feedback': feedback
        }
    })


@app.route('/api/simulation/status', methods=['GET'])
@jwt_required()
def get_simulation_status():
    user_id = int(get_jwt_identity())  # Convert string back to int

    # Get latest round
    latest_round = SimulationRound.query.filter_by(user_id=user_id).order_by(
        SimulationRound.round_number.desc()).first()

    if not latest_round:
        return jsonify({'message': 'No simulation found. Start a new simulation.'}), 404

    # Get decisions for this round
    decisions = Decision.query.filter_by(user_id=user_id, round_number=latest_round.round_number).all()

    decision_summary = []
    for decision in decisions:
        decision_summary.append({
            'type': decision.decision_type,
            'budget_allocated': decision.budget_allocated,
            'hires_made': decision.hires_made
        })

    return jsonify({
        'current_round': latest_round.round_number,
        'budget': latest_round.budget,
        'satisfaction_score': latest_round.satisfaction_score,
        'turnover_rate': round(latest_round.turnover_rate * 100, 1),
        'time_to_fill': latest_round.time_to_fill,
        'decisions': decision_summary
    })


# Web Interface Routes (for Dr. Cooper)

@app.route('/web')
def web_home():
    return redirect(url_for('web_login'))


@app.route('/web/register', methods=['GET', 'POST'])
def web_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')

        # Create new user
        password_hash = generate_password_hash(password)
        new_user = User(username=username, password_hash=password_hash, role='user')
        db.session.add(new_user)
        db.session.commit()

        return render_template('register.html', success='Registration successful! You can now login.')

    return render_template('register.html')


@app.route('/web/login', methods=['GET', 'POST'])
def web_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('web_dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')


@app.route('/web/dashboard')
def web_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('web_login'))

    user_id = session['user_id']

    # Get latest round
    latest_round = SimulationRound.query.filter_by(user_id=user_id).order_by(
        SimulationRound.round_number.desc()).first()

    # If no round exists, create Round 1
    if not latest_round:
        latest_round = SimulationRound(
            user_id=user_id,
            round_number=1,
            budget=500000,
            satisfaction_score=50,  # Starting baseline
            turnover_rate=0.12,  # Starting baseline
            time_to_fill=30  # Starting baseline
        )
        db.session.add(latest_round)
        db.session.commit()

    # Get decisions for current round
    decisions = Decision.query.filter_by(user_id=user_id, round_number=latest_round.round_number).all()

    # Round is completed only if there are decisions made
    round_completed = len(decisions) > 0

    return render_template('dashboard.html',
                           username=session['username'],
                           round_data=latest_round,
                           decisions=decisions,
                           round_completed=round_completed)


@app.route('/web/debug-db')
def debug_db():
    # Get all users
    users = User.query.all()
    rounds = SimulationRound.query.all()
    decisions = Decision.query.all()

    output = "<h2>Database Contents</h2>"

    output += "<h3>Users:</h3>"
    for user in users:
        output += f"<p>ID: {user.id}, Username: {user.username}, Role: {user.role}</p>"

    output += "<h3>Simulation Rounds:</h3>"
    for round in rounds:
        output += f"<p>ID: {round.id}, User: {round.user_id}, Round: {round.round_number}, Satisfaction: {round.satisfaction_score}%</p>"

    output += "<h3>Decisions:</h3>"
    for decision in decisions:
        output += f"<p>ID: {decision.id}, User: {decision.user_id}, Round: {decision.round_number}, Type: {decision.decision_type}, Budget: ${decision.budget_allocated}</p>"

    output += '<br><a href="/web/dashboard">Back to Dashboard</a>'

    return output


@app.route('/web/clear-db')
def clear_db():
    # Delete all data from all tables
    Decision.query.delete()
    SimulationRound.query.delete()
    User.query.delete()
    db.session.commit()

    return '''
    <h2>Database Cleared!</h2>
    <p>All users, rounds, and decisions have been deleted.</p>
    <a href="/web/register">Create New Account</a> | 
    <a href="/web">Go to Login</a>
    '''


@app.route('/web/recruit', methods=['POST'])
def web_recruit():
    if 'user_id' not in session:
        return redirect(url_for('web_login'))

    user_id = session['user_id']
    recruitment_budget = float(request.form['recruitment_budget'])
    round_number = int(request.form.get('round_number', 1))

    # CHECK: Prevent multiple decisions in the same round
    existing_decision = Decision.query.filter_by(
        user_id=user_id,
        round_number=round_number,
        decision_type='recruitment'
    ).first()

    if existing_decision:
        # Decision already made for this round
        return redirect(url_for('web_dashboard'))

    # Rest of your existing recruitment logic...
    hires_made = int(recruitment_budget / 5000)
    cost_per_hire = 5000 if hires_made > 0 else 0

    decision_quality = min(recruitment_budget / 100000, 1.0)
    time_to_fill_improvement = decision_quality * 10
    new_time_to_fill = max(20, 30 - time_to_fill_improvement)

    if hires_made > 0:
        satisfaction_improvement = hires_made * 2
        turnover_improvement = hires_made * 0.005
    else:
        satisfaction_improvement = -5
        turnover_improvement = -0.02

    # Get or create current round
    current_round = SimulationRound.query.filter_by(user_id=user_id, round_number=round_number).first()

    if not current_round:
        current_round = SimulationRound(
            user_id=user_id,
            round_number=round_number,
            budget=500000,
            satisfaction_score=50,
            turnover_rate=0.12,
            time_to_fill=30
        )
        db.session.add(current_round)

    # Update metrics
    new_satisfaction = max(0, min(100, current_round.satisfaction_score + satisfaction_improvement))
    new_turnover = max(0.02, current_round.turnover_rate - turnover_improvement)

    current_round.satisfaction_score = new_satisfaction
    current_round.turnover_rate = new_turnover
    current_round.time_to_fill = new_time_to_fill

    # Record decision
    decision = Decision(
        user_id=user_id,
        round_number=round_number,
        decision_type='recruitment',
        budget_allocated=recruitment_budget,
        hires_made=hires_made,
        cost_per_hire=cost_per_hire
    )

    db.session.add(decision)
    db.session.commit()

    return redirect(url_for('web_dashboard'))


@app.route('/web/next-round', methods=['POST'])
def web_next_round():
    if 'user_id' not in session:
        return redirect(url_for('web_login'))

    user_id = session['user_id']
    current_round_num = int(request.form.get('current_round', 1))
    next_round_num = current_round_num + 1

    if next_round_num > 3:
        return redirect(url_for('web_final_results'))

    # Create new round with fresh $500K budget
    new_round = SimulationRound(
        user_id=user_id,
        round_number=next_round_num,
        budget=500000,  # Reset budget each round
        satisfaction_score=50,  # Reset to baseline
        turnover_rate=0.12,  # Reset to baseline
        time_to_fill=30  # Reset to baseline
    )

    db.session.add(new_round)
    db.session.commit()

    return redirect(url_for('web_dashboard'))


@app.route('/web/final-results')
def web_final_results():
    if 'user_id' not in session:
        return redirect(url_for('web_login'))

    user_id = session['user_id']

    # Get all rounds for this user
    all_rounds = SimulationRound.query.filter_by(user_id=user_id).order_by(SimulationRound.round_number).all()

    # Get all decisions
    all_decisions = Decision.query.filter_by(user_id=user_id).order_by(Decision.round_number).all()

    # Calculate overall performance
    if all_rounds:
        avg_satisfaction = sum(r.satisfaction_score for r in all_rounds) / len(all_rounds)
        avg_turnover = sum(r.turnover_rate for r in all_rounds) / len(all_rounds)
        total_hires = sum(d.hires_made or 0 for d in all_decisions)
        total_spent = sum(d.budget_allocated for d in all_decisions)

        # Determine overall performance
        if avg_satisfaction > 70 and avg_turnover < 0.08:
            performance = "Excellent HR Management!"
        elif avg_satisfaction > 60 and avg_turnover < 0.12:
            performance = "Good HR Performance"
        else:
            performance = "Needs Improvement"
    else:
        avg_satisfaction = avg_turnover = total_hires = total_spent = 0
        performance = "No data"

    return render_template('final_results.html',
                           username=session['username'],
                           rounds=all_rounds,
                           decisions=all_decisions,
                           avg_satisfaction=avg_satisfaction,
                           avg_turnover=avg_turnover * 100,
                           total_hires=total_hires,
                           total_spent=total_spent,
                           performance=performance)


@app.route('/web/restart')
def web_restart():
    if 'user_id' not in session:
        return redirect(url_for('web_login'))

    user_id = session['user_id']

    # Delete all previous rounds and decisions for this user
    SimulationRound.query.filter_by(user_id=user_id).delete()
    Decision.query.filter_by(user_id=user_id).delete()
    db.session.commit()

    return redirect(url_for('web_dashboard'))


@app.route('/web/reset-all')
def reset_all():
    # Clear all simulation data (for testing only)
    SimulationRound.query.delete()
    Decision.query.delete()
    db.session.commit()
    return redirect(url_for('web_dashboard'))


@app.route('/web/debug')
def debug_data():
    if 'user_id' not in session:
        return "Not logged in"

    user_id = session['user_id']

    # Get all rounds for this user
    rounds = SimulationRound.query.filter_by(user_id=user_id).all()
    decisions = Decision.query.filter_by(user_id=user_id).all()

    debug_info = f"""
    <h2>Debug Info for User {user_id}</h2>
    <h3>Rounds ({len(rounds)}):</h3>
    """

    for round in rounds:
        debug_info += f"<p>Round {round.round_number}: Satisfaction={round.satisfaction_score}, Turnover={round.turnover_rate}</p>"

    debug_info += f"<h3>Decisions ({len(decisions)}):</h3>"

    for decision in decisions:
        debug_info += f"<p>Round {decision.round_number}: {decision.decision_type}, Budget=${decision.budget_allocated}, Hires={decision.hires_made}</p>"

    debug_info += f"""
    <br><a href="/web/force-reset">Force Reset All Data</a>
    <br><a href="/web/dashboard">Back to Dashboard</a>
    """

    return debug_info


@app.route('/web/force-reset')
def force_reset():
    if 'user_id' not in session:
        return redirect(url_for('web_login'))

    user_id = session['user_id']

    # Delete ALL data for this user
    SimulationRound.query.filter_by(user_id=user_id).delete()
    Decision.query.filter_by(user_id=user_id).delete()
    db.session.commit()

    return redirect(url_for('web_dashboard'))


@app.route('/web/logout')
def web_logout():
    session.clear()
    return redirect(url_for('web_login'))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=port, debug=False)
