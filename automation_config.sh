#!/bin/bash
# Automation configuration for cybersecurity mapping with STRIDE-CAPEC integration
# Author: ellipse2v
# Date: 2025-08-18

echo "🔧 Setting up cybersecurity mapping automation"

# Install Python dependencies
echo "📦 Installing dependencies..."

# Create requirements.txt if it doesn't exist
if [ ! -f "requirements.txt" ]; then
    echo "📝 Creating requirements.txt..."
    cat > requirements.txt << 'EOF'
requests>=2.28.0
stix2>=3.0.0
python-dateutil>=2.8.0
lxml>=4.9.0
beautifulsoup4>=4.11.0
pandas>=1.5.0
EOF
fi

# Install dependencies
pip install -r requirements.txt

# Configure cron job for daily execution
echo "⏰ Configuring cron job..."

# Get absolute path of script
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PYTHON_SCRIPT="$SCRIPT_DIR/cybersecurity_data_updater.py"

# Create cron job (daily execution at 6:00 AM)
CRON_JOB="0 6 * * * cd $SCRIPT_DIR && python3 $PYTHON_SCRIPT >> $SCRIPT_DIR/cron.log 2>&1"

# Check if task already exists
if ! crontab -l 2>/dev/null | grep -q "$PYTHON_SCRIPT"; then
    # Add cron task
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo "✅ Cron job added: daily execution at 6:00 AM"
else
    echo "ℹ️  Cron job already configured"
fi

# Create manual run script
cat > run_update.sh << 'EOF'
#!/bin/bash
# Manual update launch script

echo "🚀 Starting manual update..."
python3 cybersecurity_data_updater.py

if [ $? -eq 0 ]; then
    echo "✅ Update successful!"
    echo "📄 View report: cybersec_data/cybersec_report.html"
    echo "📊 Raw data: cybersec_data/consolidated_mapping.json"
else
    echo "❌ Error during update"
    exit 1
fi
EOF

chmod +x run_update.sh

# Create simple web deployment script
cat > deploy_web.py << 'EOF'
#!/usr/bin/env python3
"""
Simple web deployment script for the mapping report
Enhanced with STRIDE-CAPEC integration features
"""

import http.server
import socketserver
import webbrowser
import os
import json
from pathlib import Path
from datetime import datetime

PORT = 8080
REPORT_DIR = "cybersec_data"

def print_stats():
    """Print statistics from the latest mapping data"""
    mapping_file = os.path.join(REPORT_DIR, "consolidated_mapping.json")
    
    if os.path.exists(mapping_file):
        try:
            with open(mapping_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            print("\n📊 Current Data Statistics:")
            print("=" * 40)
            stats = data.get('metadata', {}).get('data_sources', {})
            framework_stats = data.get('framework_stats', {})
            
            print(f"ATT&CK Techniques: {stats.get('attack_techniques_count', 'N/A')}")
            print(f"CAPEC Patterns: {stats.get('capec_patterns_count', 'N/A')}")
            print(f"STRIDE-CAPEC Mappings: {framework_stats.get('total_capec_mapped', 'N/A')}")
            print(f"STRIDE-ATT&CK Mappings: {framework_stats.get('total_attack_mapped', 'N/A')}")
            print(f"Last Update: {data.get('metadata', {}).get('generated_at', 'N/A')}")
            
            print("\n🎯 STRIDE Category Coverage:")
            for category, stats in framework_stats.get('coverage_by_category', {}).items():
                print(f"  {category}: {stats.get('capec_count', 0)} CAPEC + {stats.get('attack_count', 0)} ATT&CK")
            
        except Exception as e:
            print(f"⚠️  Could not read statistics: {e}")

def start_server():
    """Start local web server to view the report"""
    
    if not os.path.exists(REPORT_DIR):
        print(f"❌ Directory {REPORT_DIR} not found. Run the update script first.")
        return
    
    print_stats()
    
    os.chdir(REPORT_DIR)
    
    handler = http.server.SimpleHTTPRequestHandler
    
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"\n🌐 Web server started on http://localhost:{PORT}")
        print(f"📄 Report available: http://localhost:{PORT}/cybersec_report.html")
        print(f"📊 Raw JSON data: http://localhost:{PORT}/consolidated_mapping.json")
        print("🔴 Press Ctrl+C to stop the server")
        
        # Automatically open browser
        webbrowser.open(f"http://localhost:{PORT}/cybersec_report.html")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n👋 Server stopped")

if __name__ == "__main__":
    start_server()
EOF

chmod +x deploy_web.py

# Create enhanced monitoring script
cat > monitor.sh << 'EOF'
#!/bin/bash
# Enhanced monitoring script for cybersecurity updates

echo "📊 Cybersecurity Update Monitoring"
echo "=================================="

# Check last execution
if [ -f "cybersec_data/consolidated_mapping.json" ]; then
    LAST_UPDATE=$(python3 -c "
import json
from datetime import datetime
try:
    with open('cybersec_data/consolidated_mapping.json', 'r') as f:
        data = json.load(f)
    update_time = data['metadata']['generated_at']
    print(update_time)
    
    # Parse and show time difference
    from datetime import datetime, timezone
    import dateutil.parser
    update_dt = dateutil.parser.parse(update_time)
    now = datetime.now(timezone.utc)
    diff = now - update_dt
    print(f'({diff.days} days, {diff.seconds//3600} hours ago)')
except Exception as e:
    print('Unknown')
    print(f'Error: {e}')
")
    echo "🕐 Last update: $LAST_UPDATE"
    
    # Show mapping statistics
    python3 -c "
import json
try:
    with open('cybersec_data/consolidated_mapping.json', 'r') as f:
        data = json.load(f)
    
    stats = data.get('framework_stats', {})
    sources = data.get('metadata', {}).get('data_sources', {})
    
    print('\\n📈 Current Statistics:')
    print(f'  STRIDE-CAPEC Mappings: {stats.get(\"total_capec_mapped\", \"N/A\")}')
    print(f'  STRIDE-ATT&CK Mappings: {stats.get(\"total_attack_mapped\", \"N/A\")}')
    print(f'  Total ATT&CK Techniques: {sources.get(\"attack_techniques_count\", \"N/A\")}')
    print(f'  Total CAPEC Patterns: {sources.get(\"capec_patterns_count\", \"N/A\")}')
    
    print('\\n🎯 Coverage by STRIDE Category:')
    for category, coverage in stats.get('coverage_by_category', {}).items():
        capec_count = coverage.get('capec_count', 0)
        attack_count = coverage.get('attack_count', 0)
        print(f'  {category:20}: {capec_count:3} CAPEC + {attack_count:3} ATT&CK')
        
except Exception as e:
    print(f'Error reading statistics: {e}')
"
else
    echo "❌ No update found"
fi

# Check error logs
if [ -f "cybersec_update.log" ]; then
    ERROR_COUNT=$(grep -c "ERROR" cybersec_update.log)
    WARNING_COUNT=$(grep -c "WARNING" cybersec_update.log)
    echo -e "\n⚠️  Log Analysis:"
    echo "  Errors: $ERROR_COUNT"
    echo "  Warnings: $WARNING_COUNT"
    
    if [ $ERROR_COUNT -gt 0 ]; then
        echo -e "\n🔍 Recent errors:"
        grep "ERROR" cybersec_update.log | tail -3
    fi
    
    if [ $WARNING_COUNT -gt 0 ]; then
        echo -e "\n⚠️  Recent warnings:"
        grep "WARNING" cybersec_update.log | tail -3
    fi
fi

# Check generated files
if [ -d "cybersec_data" ]; then
    echo -e "\n📂 Generated files:"
    ls -la cybersec_data/ | grep -E '\.(json|html)$' | while read line; do
        echo "  $line"
    done
    
    # Check file sizes
    echo -e "\n💾 File sizes:"
    if [ -f "cybersec_data/consolidated_mapping.json" ]; then
        SIZE=$(du -h cybersec_data/consolidated_mapping.json | cut -f1)
        echo "  Consolidated mapping: $SIZE"
    fi
    if [ -f "cybersec_data/cybersec_report.html" ]; then
        SIZE=$(du -h cybersec_data/cybersec_report.html | cut -f1)
        echo "  HTML report: $SIZE"
    fi
fi

# Check cron job status
echo -e "\n⏰ Cron job status:"
if crontab -l 2>/dev/null | grep -q cybersecurity_data_updater.py; then
    echo "  ✅ Cron job configured"
    crontab -l | grep cybersecurity_data_updater.py
else
    echo "  ❌ No cron job configured"
fi

# Network connectivity check
echo -e "\n🌐 Connectivity check:"
if curl -s --head https://github.com/mitre-attack/attack-stix-data >/dev/null; then
    echo "  ✅ ATT&CK repository accessible"
else
    echo "  ❌ ATT&CK repository not accessible"
fi

if curl -s --head https://github.com/mitre/cti >/dev/null; then
    echo "  ✅ CAPEC repository accessible"
else
    echo "  ❌ CAPEC repository not accessible"
fi

# Check Python dependencies
echo -e "\n🐍 Python dependencies:"
python3 -c "
import sys
dependencies = ['requests', 'stix2', 'dateutil', 'lxml', 'bs4', 'pandas']
missing = []

for dep in dependencies:
    try:
        __import__(dep if dep != 'dateutil' else 'dateutil.parser')
        print(f'  ✅ {dep}')
    except ImportError:
        print(f'  ❌ {dep} (missing)')
        missing.append(dep)

if missing:
    print(f'\\nRun: pip install {\" \".join(missing)}')
"
EOF

chmod +x monitor.sh

# Create configuration validator
cat > validate_setup.py << 'EOF'
#!/usr/bin/env python3
"""
Setup validation script for cybersecurity mapping automation
"""

import os
import sys
import json
import subprocess
import requests
from datetime import datetime

def check_dependencies():
    """Check if all required Python packages are installed"""
    print("🐍 Checking Python dependencies...")
    
    required_packages = [
        'requests', 'stix2', 'dateutil', 'lxml', 'bs4', 'pandas'
    ]
    
    missing = []
    for package in required_packages:
        try:
            if package == 'dateutil':
                import dateutil.parser
            elif package == 'bs4':
                import bs4
            else:
                __import__(package)
            print(f"  ✅ {package}")
        except ImportError:
            print(f"  ❌ {package} (missing)")
            missing.append(package)
    
    return missing

def check_network_access():
    """Check network access to required sources"""
    print("\n🌐 Checking network access...")
    
    sources = {
        'ATT&CK Enterprise': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
        'CAPEC STIX': 'https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json',
        'GitHub (general)': 'https://github.com'
    }
    
    accessible = []
    for name, url in sources.items():
        try:
            response = requests.head(url, timeout=10)
            if response.status_code < 400:
                print(f"  ✅ {name}")
                accessible.append(name)
            else:
                print(f"  ⚠️  {name} (HTTP {response.status_code})")
        except Exception as e:
            print(f"  ❌ {name} (error: {e})")
    
    return accessible

def check_file_structure():
    """Check if required files exist"""
    print("\n📂 Checking file structure...")
    
    required_files = [
        'cybersecurity_data_updater.py',
        'requirements.txt',
        'run_update.sh',
        'deploy_web.py',
        'monitor.sh'
    ]
    
    existing = []
    for file in required_files:
        if os.path.exists(file):
            print(f"  ✅ {file}")
            existing.append(file)
        else:
            print(f"  ❌ {file} (missing)")
    
    return existing

def test_mapping_capabilities():
    """Test STRIDE-CAPEC mapping capabilities"""
    print("\n🎯 Testing STRIDE-CAPEC mapping...")
    
    try:
        # Import the updater class
        sys.path.append('.')
        from cybersecurity_data_updater import CybersecurityDataUpdater
        
        updater = CybersecurityDataUpdater()
        
        # Check STRIDE categories
        stride_count = len(updater.stride_capec_mappings)
        print(f"  ✅ STRIDE categories loaded: {stride_count}")
        
        # Check CAPEC mappings
        total_capec = sum(len(mapping['capec_ids']) for mapping in updater.stride_capec_mappings.values())
        print(f"  ✅ Total CAPEC mappings: {total_capec}")
        
        # Show category breakdown
        for category, mapping in updater.stride_capec_mappings.items():
            count = len(mapping['capec_ids'])
            print(f"    {category}: {count} CAPEC patterns")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Mapping test failed: {e}")
        return False

def run_validation():
    """Run complete validation"""
    print("🔍 Cybersecurity Mapping Setup Validation")
    print("=" * 50)
    
    # Check dependencies
    missing_deps = check_dependencies()
    
    # Check network
    accessible_sources = check_network_access()
    
    # Check files
    existing_files = check_file_structure()
    
    # Test mappings
    mapping_ok = test_mapping_capabilities()
    
    # Summary
    print(f"\n📋 Validation Summary")
    print("=" * 30)
    
    if not missing_deps:
        print("✅ All Python dependencies installed")
    else:
        print(f"❌ Missing dependencies: {', '.join(missing_deps)}")
        print(f"   Run: pip install {' '.join(missing_deps)}")
    
    print(f"✅ Network sources accessible: {len(accessible_sources)}/3")
    print(f"✅ Required files present: {len(existing_files)}/5")
    
    if mapping_ok:
        print("✅ STRIDE-CAPEC mapping system functional")
    else:
        print("❌ STRIDE-CAPEC mapping system has issues")
    
    # Overall status
    all_good = (not missing_deps and len(accessible_sources) >= 2 and 
                len(existing_files) >= 4 and mapping_ok)
    
    if all_good:
        print("\n🎉 Setup validation PASSED!")
        print("You can now run: ./run_update.sh")
    else:
        print("\n⚠️  Setup validation has issues. Please fix the problems above.")
    
    return all_good

if __name__ == "__main__":
    run_validation()
EOF

chmod +x validate_setup.py

# Create logs directory
mkdir -p logs
touch logs/update.log

# Setup summary
echo ""
echo "🎉 Enhanced setup completed!"
echo "=========================="
echo ""
echo "📝 Files created:"
echo "  • cybersecurity_data_updater.py - Main script with STRIDE-CAPEC mapping"
echo "  • requirements.txt - Python dependencies"
echo "  • run_update.sh - Manual execution"
echo "  • deploy_web.py - Enhanced web server"
echo "  • monitor.sh - Comprehensive monitoring"
echo "  • validate_setup.py - Setup validation"
echo ""
echo "🚀 Available commands:"
echo "  • ./run_update.sh           - Manual update"
echo "  • python3 deploy_web.py     - View report with statistics"
echo "  • ./monitor.sh              - Check system status"
echo "  • python3 validate_setup.py - Validate installation"
echo ""
echo "⏰ Automation:"
echo "  • Daily update at 6:00 AM (cron job)"
echo "  • Enhanced logging in cybersec_update.log"
echo "  • STRIDE-CAPEC official mappings included"
echo ""
echo "🎯 New features:"
echo "  • Official STRIDE to CAPEC mappings (400+ patterns)"
echo "  • Enhanced HTML report with statistics"
echo "  • Coverage analysis by threat category"
echo "  • Real-time data validation"
echo ""
echo "🔍 First run recommended:"
echo "  python3 validate_setup.py && ./run_update.sh"
