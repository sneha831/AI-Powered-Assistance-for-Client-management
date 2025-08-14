# 🏥 Medical Data Integrity & Issue Management System

An advanced AI-powered system that combines medical data anomaly detection with intelligent issue classification and management, featuring role-based authentication for clients and administrators.

## 🎯 System Overview

This system addresses the requirements from your project description by combining:

**Idea 1**: Medical Data Integrity & Anomaly Detection System
**Idea 2**: Intelligent Software Issue Classifier & Prioritizer

### Key Features

#### 🔍 **Data Anomaly Detection**

- AI-powered analysis of medical and business data
- Detects age anomalies, billing irregularities, missing data, and vital sign abnormalities
- Real-time pattern recognition and data validation
- Automated severity classification (Low, Medium, High, Critical)

#### 🤖 **Intelligent Issue Classification**

- Automatic priority assignment based on content analysis
- Smart categorization (System, Data, Security, Performance)
- AI-generated analysis and recommendations
- Critical issue alerts for patient safety and system security

#### 👥 **Dual Authentication System**

- **Client Role**: Report issues, analyze data, view personal dashboard
- **Admin Role**: Manage all issues, resolve problems, system oversight
- Secure authentication with password hashing and session management

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Database Configuration

The system uses SQLite by default for development (no setup required).

For production PostgreSQL:

1. Install PostgreSQL
2. Create database: `createdb medical_system`
3. Update `.env` with your connection string:

```bash
DATABASE_URL=postgresql://username:password@localhost:5432/medical_system
```

### 3. Run the Application

```bash
# Ensure virtual environment is active
source venv/bin/activate

# Start the application
python app.py
```

### 4. Access the System

Open your browser: `http://127.0.0.1:5000`

## 📊 How It Works

### For Clients:

1. **Sign Up** → Choose "Client" role
2. **Analyze Data** → Paste medical/business data for anomaly detection
3. **Report Issues** → Describe problems for AI classification
4. **Track Progress** → Monitor issue resolution status

### For Administrators:

1. **Sign Up** → Choose "Admin" role
2. **View Dashboard** → See all issues and anomalies
3. **Manage Issues** → Review AI analysis and resolve problems
4. **Monitor System** → Track statistics and critical alerts

## 🧠 AI Analysis Examples

### Data Anomaly Detection

```
Input Data:
Patient ID: 12345
Name: John Doe
Age: 200
Blood Pressure: 250/130
Billing: ₹15,00,000
Status: null

AI Detection:
✅ Unusual age detected: 200 (Medium)
✅ Critical blood pressure: 250/130 (Critical)
✅ High billing amount: ₹15,00,000 (High)
✅ Missing data indicator: "null" (Medium)
```

### Issue Classification

```
Input: "System freeze during payment processing - urgent!"

AI Analysis:
Priority: Critical ⚠️
Category: System Error
Team: Backend
Recommendation: Immediate system audit recommended
```

## 🏗️ System Architecture

### Database Models

- **User**: Authentication and role management
- **Issue**: Problem reports with AI analysis
- **DataAnomaly**: Detected data irregularities

### AI Functions

- `analyze_issue_priority()`: Keyword-based priority detection
- `categorize_issue()`: Smart issue categorization
- `analyze_medical_data()`: Medical data anomaly detection
- `generate_ai_analysis()`: Automated recommendations

### Security Features

- Password hashing with Werkzeug
- CSRF protection with Flask-WTF
- Role-based access control
- Session management with Flask-Login

## 📁 Project Structure

```
├── app.py                     # Main Flask application
├── requirements.txt           # Python dependencies
├── .env                      # Environment configuration
├── templates/
│   ├── base.html            # Base template with navigation
│   ├── index.html           # Landing page
│   ├── auth/                # Authentication templates
│   │   ├── login.html
│   │   └── signup.html
│   ├── client/              # Client interface
│   │   ├── dashboard.html
│   │   ├── analyze_data.html
│   │   └── report_issue.html
│   └── admin/               # Admin interface
│       └── dashboard.html
├── static/
│   ├── css/style.css       # Modern styling
│   └── js/main.js          # JavaScript functionality
└── README.md               # This file
```

## 🎮 Testing the System

### Test Data Anomaly Detection:

```
Patient Name: Jane Smith
Age: 150
Blood Pressure: 220/120
Billing Amount: ₹12,00,000
Lab Results: missing
Status: null
```

### Test Issue Classification:

- **Critical**: "Security breach - patient data compromised!"
- **High**: "System error - database connection failed"
- **Medium**: "Performance issue - slow loading times"
- **Low**: "Minor UI cosmetic issue"

## 🔧 Configuration Options

### Environment Variables (.env)

```bash
# Database (SQLite default, PostgreSQL for production)
DATABASE_URL=sqlite:///medical_system.db

# Security
SECRET_KEY=your-secret-key-change-in-production

# Flask Settings
FLASK_ENV=development
FLASK_DEBUG=True
```

### Supported Databases

- **SQLite** (Development) - Zero setup required
- **PostgreSQL** (Production) - Requires `psycopg2-binary`

## 🚀 Production Deployment

1. **Set Production Environment**:

```bash
FLASK_ENV=production
FLASK_DEBUG=False
```

2. **Use PostgreSQL**:

```bash
DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

3. **Security**:
   - Change `SECRET_KEY` to a strong random value
   - Use HTTPS in production
   - Set up proper database backups

## 💡 Key Benefits

✅ **Dual Functionality**: Combines data analysis with issue management  
✅ **AI-Powered**: Automatic classification and priority assignment  
✅ **Role-Based**: Separate client and admin interfaces  
✅ **Medical Focus**: Specialized for healthcare data patterns  
✅ **Real-time**: Instant analysis and alerts  
✅ **Scalable**: Database-backed with proper architecture

---

**Built for Intelligence Science** - Combining medical expertise with AI technology for better data integrity and issue management.

Made with ❤️ for learning modern web development, AI integration, and healthcare systems.
