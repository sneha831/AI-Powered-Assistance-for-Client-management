import os
import re
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, SelectField, RadioField
from wtforms.fields import DateField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import openai

# Load environment variables
load_dotenv()

# Initialize OpenAI
openai.api_key = os.getenv('OPENAI_API_KEY')

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    
    # Handle database URL - ensure SQLite fallback
    database_url = os.getenv('DATABASE_URL', 'sqlite:///medical_system.db')
    
    # If PostgreSQL URL but no psycopg2, fallback to SQLite
    if database_url.startswith(('postgres://', 'postgresql://')):
        try:
            import psycopg2
            # If psycopg2 is available, fix the URL format
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
        except ImportError:
            print("PostgreSQL driver not found. Falling back to SQLite...")
            database_url = 'sqlite:///medical_system.db'
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    
    return app

app = create_app()

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='client')  # 'client' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships - explicitly specify foreign keys to avoid ambiguity
    issues = db.relationship('Issue', foreign_keys='Issue.reporter_id', backref='reporter', lazy=True)
    resolved_issues = db.relationship('Issue', foreign_keys='Issue.resolved_by', backref='resolver', lazy=True)
    data_anomalies = db.relationship('DataAnomaly', backref='reporter', lazy=True)

class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), default='Low')  # Low, Medium, High, Critical
    status = db.Column(db.String(20), default='Open')  # Open, In Progress, Resolved
    category = db.Column(db.String(50), default='General')
    domain = db.Column(db.String(50), default='other')  # AI-detected domain (coding, plumbing, etc.)
    ai_analysis = db.Column(db.Text)  # AI-generated analysis
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    deadline = db.Column(db.DateTime) # Added deadline field

class DataAnomaly(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_source = db.Column(db.String(100), nullable=False)
    anomaly_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='Medium')
    raw_data = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Detected')
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class SignupForm(FlaskForm):
    username = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    company_name = StringField('Company Name', validators=[DataRequired(), Length(min=2, max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    role = SelectField('Role', choices=[('client', 'Client'), ('admin', 'Admin')], default='client')

class IssueForm(FlaskForm):
    title = StringField('Issue Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('bug', 'Bug Report'),
        ('feature', 'Feature Request'),
        ('support', 'Support Request'),
        ('security', 'Security Issue'),
        ('performance', 'Performance Issue'),
        ('other', 'Other')
    ], default='bug')
    deadline = DateField('Deadline (YYYY-MM-DD)') # Added deadline field to form

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# AI Analysis Functions using OpenAI
def analyze_issue_with_openai(title, description):
    """Use OpenAI to analyze issue criticality and domain"""
    try:
        client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        
        prompt = f"""
        Analyze this support issue and provide a JSON response with the following structure:
        {{
            "priority": "Critical|High|Medium|Low",
            "domain": "coding|plumbing|electrical|hvac|security|network|hardware|software|facilities|other",
            "category": "bug|feature|support|security|performance|infrastructure|maintenance|other",
            "reasoning": "Brief explanation of why this priority and domain were assigned"
        }}

        Issue Title: {title}
        Issue Description: {description}

        Guidelines:
        - Critical: System down, security breach, data loss, safety hazard, complete service outage
        - High: Major functionality broken, significant performance issues, partial outages
        - Medium: Minor bugs, feature requests, moderate performance issues
        - Low: Cosmetic issues, documentation, minor enhancements

        Domain Guidelines:
        - coding: Software bugs, application errors, API issues, database problems
        - plumbing: Water leaks, pipe issues, drainage problems, water pressure
        - electrical: Power outages, wiring issues, electrical equipment failures
        - hvac: Heating, ventilation, air conditioning, temperature control
        - security: Access control, surveillance, locks, security breaches
        - network: Internet connectivity, WiFi, network equipment, bandwidth
        - hardware: Computer equipment, printers, physical device failures
        - software: Application issues, software installation, licensing
        - facilities: Building maintenance, cleaning, space management
        - other: Issues that don't fit other categories

        Provide only the JSON response, no additional text.
        """

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an expert support ticket analyzer. Analyze issues and categorize them by priority and domain. Always respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.1
        )
        
        # Parse the JSON response
        analysis = json.loads(response.choices[0].message.content.strip())
        
        return {
            'priority': analysis.get('priority', 'Medium'),
            'domain': analysis.get('domain', 'other'),
            'category': analysis.get('category', 'support'),
            'reasoning': analysis.get('reasoning', 'AI analysis completed')
        }
        
    except Exception as e:
        print(f"OpenAI API Error: {e}")
        # Fallback to simple analysis if OpenAI fails
        return fallback_analysis(title, description)

def fallback_analysis(title, description):
    """Fallback analysis if OpenAI is unavailable"""
    text = (title + " " + description).lower()
    
    # Simple keyword-based analysis as fallback
    if any(word in text for word in ['down', 'outage', 'critical', 'urgent', 'security breach', 'data loss']):
        priority = 'Critical'
    elif any(word in text for word in ['error', 'broken', 'not working', 'failed', 'crash']):
        priority = 'High'
    elif any(word in text for word in ['slow', 'performance', 'improvement']):
        priority = 'Medium'
    else:
        priority = 'Low'
    
    # Simple domain detection
    if any(word in text for word in ['code', 'bug', 'software', 'application', 'api', 'database']):
        domain = 'coding'
    elif any(word in text for word in ['leak', 'water', 'pipe', 'plumbing', 'drainage']):
        domain = 'plumbing'
    elif any(word in text for word in ['power', 'electrical', 'electricity', 'wiring']):
        domain = 'electrical'
    elif any(word in text for word in ['network', 'internet', 'wifi', 'connection']):
        domain = 'network'
    elif any(word in text for word in ['security', 'access', 'login', 'password']):
        domain = 'security'
    else:
        domain = 'other'
    
    return {
        'priority': priority,
        'domain': domain,
        'category': 'support',
        'reasoning': 'Fallback analysis - OpenAI unavailable'
    }

def generate_ai_analysis(title, description, ai_result):
    """Generate comprehensive AI analysis summary"""
    priority = ai_result['priority']
    domain = ai_result['domain']
    category = ai_result['category']
    reasoning = ai_result['reasoning']
    
    analysis = f"🤖 AI-Powered Analysis:\n\n"
    analysis += f"📊 Priority Level: {priority}\n"
    analysis += f"🏷️ Domain: {domain.title()}\n"
    analysis += f"📂 Category: {category.title()}\n\n"
    
    # Priority-based alerts
    if priority == 'Critical':
        analysis += "🚨 CRITICAL ALERT: Immediate attention required!\n"
        analysis += "⏰ Response Time: < 1 hour\n"
        analysis += "👥 Escalation: Notify senior team immediately\n\n"
    elif priority == 'High':
        analysis += "🔴 HIGH PRIORITY: Significant impact detected\n"
        analysis += "⏰ Response Time: < 4 hours\n"
        analysis += "👥 Escalation: Assign to experienced technician\n\n"
    elif priority == 'Medium':
        analysis += "🟡 MEDIUM PRIORITY: Moderate impact\n"
        analysis += "⏰ Response Time: < 24 hours\n"
        analysis += "👥 Escalation: Standard workflow\n\n"
    else:
        analysis += "🟢 LOW PRIORITY: Minor impact\n"
        analysis += "⏰ Response Time: < 72 hours\n"
        analysis += "👥 Escalation: Can be handled during maintenance\n\n"
    
    # Domain-specific recommendations
    domain_recommendations = {
        'coding': "💻 Recommended Actions: Code review, debugging, testing in dev environment",
        'plumbing': "🔧 Recommended Actions: Inspect pipes, check water pressure, contact plumber if needed",
        'electrical': "⚡ Recommended Actions: Check circuit breakers, inspect wiring, ensure safety protocols",
        'hvac': "🌡️ Recommended Actions: Check thermostat, inspect filters, verify system operation",
        'security': "🔒 Recommended Actions: Security audit, access review, update credentials",
        'network': "🌐 Recommended Actions: Check connectivity, restart equipment, monitor bandwidth",
        'hardware': "🖥️ Recommended Actions: Hardware diagnostics, check connections, replacement if needed",
        'software': "💿 Recommended Actions: Software update, reinstallation, license verification",
        'facilities': "🏢 Recommended Actions: Facility inspection, maintenance scheduling, vendor contact",
        'other': "📋 Recommended Actions: General assessment, appropriate team assignment"
    }
    
    analysis += domain_recommendations.get(domain, domain_recommendations['other'])
    analysis += f"\n\n🧠 AI Reasoning: {reasoning}"
    
    return analysis

# Legacy function names for backward compatibility
def analyze_issue_priority(title, description):
    """Wrapper for backward compatibility"""
    result = analyze_issue_with_openai(title, description)
    return result['priority']

def categorize_issue(title, description):
    """Wrapper for backward compatibility"""
    result = analyze_issue_with_openai(title, description)
    return result['category']

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('client_dashboard'))
        flash('Invalid email or password', 'error')
    return render_template('auth/login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Name already exists', 'error')
            return render_template('auth/signup.html', form=form)
        
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered', 'error')
            return render_template('auth/signup.html', form=form)
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            company_name=form.company_name.data,
            password_hash=generate_password_hash(form.password.data),
            role=form.role.data
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('client_dashboard'))
    return render_template('auth/signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/client-dashboard')
@login_required
def client_dashboard():
    if current_user.role != 'client':
        return redirect(url_for('admin_dashboard'))
    
    user_issues = Issue.query.filter_by(reporter_id=current_user.id).order_by(Issue.created_at.desc()).all()
    
    return render_template('client/dashboard.html', issues=user_issues)

@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('client_dashboard'))
    
    all_issues = Issue.query.order_by(Issue.created_at.desc()).all()
    
    # Statistics
    stats = {
        'total_issues': Issue.query.count(),
        'open_issues': Issue.query.filter_by(status='Open').count()
    }
    
    return render_template('admin/dashboard.html', issues=all_issues, stats=stats)

@app.route('/report-issue', methods=['GET', 'POST'])
@login_required
def report_issue():
    form = IssueForm()
    if form.validate_on_submit():
        # AI Analysis
        ai_result = analyze_issue_with_openai(form.title.data, form.description.data)
        ai_analysis = generate_ai_analysis(form.title.data, form.description.data, ai_result)
        
        issue = Issue(
            title=form.title.data,
            description=form.description.data,
            priority=ai_result['priority'],
            category=ai_result['category'],
            domain=ai_result['domain'],
            ai_analysis=ai_analysis,
            reporter_id=current_user.id,
            deadline=form.deadline.data # Save deadline from form
        )
        db.session.add(issue)
        db.session.commit()
        flash('Issue reported successfully! AI analysis completed.', 'success')
        return redirect(url_for('client_dashboard'))
    return render_template('client/report_issue.html', form=form)

@app.route('/resolve-issue/<int:issue_id>')
@login_required
def resolve_issue(issue_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('client_dashboard'))
    
    issue = Issue.query.get_or_404(issue_id)
    issue.status = 'Resolved'
    issue.resolved_at = datetime.utcnow()
    issue.resolved_by = current_user.id
    
    db.session.commit()
    flash('Issue marked as resolved!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/issue/<int:issue_id>')
@login_required
def view_issue(issue_id):
    issue = Issue.query.get_or_404(issue_id)
    
    # Check permissions
    if current_user.role != 'admin' and issue.reporter_id != current_user.id:
        flash('Access denied.', 'error')
        return redirect(url_for('client_dashboard'))
    
    return render_template('issue_detail.html', issue=issue)

# Create tables
def migrate_database():
    """Migrate database schema to match current models"""
    try:
        # Check if domain column exists in issue table
        with db.engine.connect() as conn:
            result = conn.execute(db.text("PRAGMA table_info(issue)"))
            columns = [row[1] for row in result.fetchall()]
            
            # Add missing columns if they don't exist
            if 'domain' not in columns:
                print("Adding 'domain' column to issue table...")
                conn.execute(db.text("ALTER TABLE issue ADD COLUMN domain VARCHAR(50) DEFAULT 'other'"))
                conn.commit()
                print("✓ Added 'domain' column")
            
            if 'ai_analysis' not in columns:
                print("Adding 'ai_analysis' column to issue table...")
                conn.execute(db.text("ALTER TABLE issue ADD COLUMN ai_analysis TEXT"))
                conn.commit()
                print("✓ Added 'ai_analysis' column")
                
            if 'deadline' not in columns: # Add check for deadline column
                print("Adding 'deadline' column to issue table...")
                conn.execute(db.text("ALTER TABLE issue ADD COLUMN deadline DATETIME"))
                conn.commit()
                print("✓ Added 'deadline' column")
                
    except Exception as e:
        print(f"Migration error: {e}")
        print("Attempting to recreate database...")
        # Drop all tables and recreate
        db.drop_all()
        db.create_all()
        print("✓ Database recreated successfully!")

with app.app_context():
    try:
        # First try to create tables
        db.create_all()
        print("Database tables created successfully!")
        
        # Then run migrations to ensure schema is up to date
        migrate_database()
        
    except Exception as e:
        print(f"Database error: {e}")
        print("Falling back to SQLite...")
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///medical_system.db'
        db.init_app(app)
        
        try:
            db.create_all()
            print("✓ SQLite database created successfully!")
            migrate_database()
        except Exception as e2:
            print(f"SQLite creation failed: {e2}")
            print("Please delete the existing database file and restart the application.")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)