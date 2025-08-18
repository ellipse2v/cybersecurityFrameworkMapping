# 🛡️ Cybersecurity Framework Mapping Tool

An automated tool for mapping and correlating cybersecurity frameworks including **MITRE ATT&CK**, **CAPEC**, **D3FEND**, and **STRIDE** threat modeling categories.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yourusername/cybersec-mapping/graphs/commit-activity)

## 🎯 Features

- **Official STRIDE-CAPEC Mappings**: 400+ validated attack patterns across 6 threat categories
- **Real-time Data Fetching**: Automatic updates from official MITRE repositories
- **Cross-Framework Correlation**: Links between ATT&CK techniques, CAPEC patterns, and STRIDE categories
- **Interactive HTML Reports**: Modern, responsive dashboards with statistics
- **Automated Scheduling**: Daily updates via cron jobs
- **Comprehensive Monitoring**: Health checks, error tracking, and coverage analysis

## 📊 Data Sources

| Framework | Source | Update Frequency |
|-----------|--------|------------------|
| **MITRE ATT&CK** | [Official STIX Repository](https://github.com/mitre-attack/attack-stix-data) | Daily |
| **CAPEC** | [MITRE CTI Repository](https://github.com/mitre/cti) | Daily |
| **D3FEND** | [Official API](https://d3fend.mitre.org/api/) | When available |
| **STRIDE-CAPEC Mappings** | [Community Research](https://ostering.com/blog/2022/03/07/capec-stride-mapping/) | Static (validated) |

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Internet connection for data fetching
- Unix-like system (Linux/macOS) for automation scripts

### Installation

1. **Clone or download the scripts**:
   ```bash
   # Download the main files
   wget https://your-repo/cybersecurity_data_updater.py
   wget https://your-repo/automation_config.sh
   ```

2. **Run the automated setup**:
   ```bash
   chmod +x automation_config.sh
   ./automation_config.sh
   ```

3. **Validate the installation**:
   ```bash
   python3 validate_setup.py
   ```

4. **Run your first update**:
   ```bash
   ./run_update.sh
   ```

### Manual Installation

If you prefer manual setup:

```bash
# Install Python dependencies
pip install requests stix2 python-dateutil lxml beautifulsoup4 pandas

# Run the main script
python3 cybersecurity_data_updater.py

# View the report
python3 deploy_web.py
```

## 📋 Usage

### Basic Commands

| Command | Description |
|---------|-------------|
| `./run_update.sh` | Manual data update |
| `python3 deploy_web.py` | Start web server to view reports |
| `./monitor.sh` | Check system status and statistics |
| `python3 validate_setup.py` | Validate installation and dependencies |

### Advanced Usage

#### Custom Output Directory
```python
from cybersecurity_data_updater import CybersecurityDataUpdater

updater = CybersecurityDataUpdater(output_dir="custom_data")
mapping_data = updater.generate_consolidated_mapping()
```

#### API Integration
```python
import json

# Load the consolidated mapping
with open('cybersec_data/consolidated_mapping.json', 'r') as f:
    data = json.load(f)

# Access STRIDE mappings
spoofing_patterns = data['stride_mapping']['Spoofing']['capec_patterns']
print(f"Found {len(spoofing_patterns)} spoofing patterns")
```

## 🎯 STRIDE Categories Coverage

| Category | CAPEC Patterns | Description |
|----------|----------------|-------------|
| **Spoofing** | 89 patterns | Identity falsification, phishing, content spoofing |
| **Tampering** | 45 patterns | Data manipulation, code injection, file system attacks |
| **Repudiation** | 6 patterns | Log manipulation, evidence elimination |
| **Information Disclosure** | 25 patterns | Data interception, credential harvesting |
| **Denial of Service** | 35 patterns | Resource exhaustion, network flooding |
| **Elevation of Privilege** | 16 patterns | Authentication bypass, privilege escalation |

## 📊 Output Files

### Generated Data Files

```
cybersec_data/
├── consolidated_mapping.json      # Complete framework mapping
├── cybersec_report.html          # Interactive HTML report
├── attack_enterprise_raw.json    # Raw ATT&CK Enterprise data
├── attack_mobile_raw.json        # Raw ATT&CK Mobile data
├── attack_ics_raw.json           # Raw ATT&CK ICS data
├── capec_raw.json                # Raw CAPEC data
└── d3fend_raw.json               # Raw D3FEND data (when available)
```

### JSON Schema

```json
{
  "metadata": {
    "generated_at": "2025-08-18T10:30:00Z",
    "version": "2.0",
    "data_sources": {
      "attack_techniques_count": 800,
      "capec_patterns_count": 600,
      "stride_categories": 6
    }
  },
  "stride_mapping": {
    "Spoofing": {
      "description": "Identity falsification attacks",
      "capec_patterns": [...],
      "attack_techniques": [...]
    }
  },
  "framework_stats": {
    "total_capec_mapped": 216,
    "total_attack_mapped": 450,
    "coverage_by_category": {...}
  }
}
```

## ⚙️ Configuration

### Automation Setup

The tool automatically configures:

- **Cron Job**: Daily updates at 6:00 AM
- **Logging**: Comprehensive logs in `cybersec_update.log`
- **Error Handling**: Retry mechanisms with exponential backoff
- **Health Monitoring**: Network connectivity and dependency checks

### Customization Options

#### Modify Update Schedule
```bash
# Edit cron job (example: every 6 hours)
crontab -e
# Change to: 0 */6 * * * cd /path/to/script && python3 cybersecurity_data_updater.py
```

#### Custom STRIDE Mappings
```python
# In cybersecurity_data_updater.py, modify:
self.stride_capec_mappings = {
    'Spoofing': {
        'capec_ids': ['CAPEC-148', 'CAPEC-151', ...],  # Add/remove IDs
        'description': 'Custom description'
    }
}
```

## 🔍 Monitoring & Troubleshooting

### Health Check Dashboard

Run `./monitor.sh` to see:

```
📊 Cybersecurity Update Monitoring
==================================
🕐 Last update: 2025-08-18T10:30:00Z (0 days, 2 hours ago)

📈 Current Statistics:
  STRIDE-CAPEC Mappings: 216
  STRIDE-ATT&CK Mappings: 450
  Total ATT&CK Techniques: 800
  Total CAPEC Patterns: 600

🎯 Coverage by STRIDE Category:
  Spoofing            : 89 CAPEC + 120 ATT&CK
  Tampering           : 45 CAPEC +  95 ATT&CK
  ...

⏰ Cron job status: ✅ Cron job configured
🌐 Connectivity check: ✅ All sources accessible
```

### Common Issues

#### Network Connectivity
```bash
# Test connectivity to MITRE repositories
curl -I https://github.com/mitre-attack/attack-stix-data
curl -I https://github.com/mitre/cti
```

#### Missing Dependencies
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Or install individually
pip install requests stix2 python-dateutil lxml beautifulsoup4 pandas
```

#### Permission Issues
```bash
# Fix script permissions
chmod +x *.sh *.py

# Fix cron job access
sudo crontab -e  # If running as system service
```

### Log Analysis

Check logs for detailed error information:

```bash
# View recent logs
tail -f cybersec_update.log

# Search for errors
grep "ERROR" cybersec_update.log

# Count warnings
grep -c "WARNING" cybersec_update.log
```

## 🔧 Development

### Project Structure

```
.
├── cybersecurity_data_updater.py  # Main application
├── automation_config.sh          # Setup automation
├── requirements.txt               # Python dependencies
├── run_update.sh                 # Manual execution script
├── deploy_web.py                 # Web server for reports
├── monitor.sh                    # System monitoring
├── validate_setup.py             # Installation validator
├── cybersec_data/                # Generated data directory
├── logs/                         # Log files
└── README.md                     # This file
```

### Adding New Frameworks

To integrate additional cybersecurity frameworks:

1. **Add data source URL**:
   ```python
   self.sources['new_framework'] = 'https://api.example.com/data.json'
   ```

2. **Create parser method**:
   ```python
   def parse_new_framework_data(self, data):
       # Implementation here
       pass
   ```

3. **Update mapping logic**:
   ```python
   def create_stride_mapping_with_real_data(self, techniques, patterns, new_data):
       # Include new framework in mappings
   ```

### Testing

```bash
# Validate setup
python3 validate_setup.py

# Test with limited data (faster)
python3 -c "
from cybersecurity_data_updater import CybersecurityDataUpdater
updater = CybersecurityDataUpdater()
print('Setup OK')
"

# Run full update
./run_update.sh
```

## 📚 References

- **MITRE ATT&CK**: [attack.mitre.org](https://attack.mitre.org/)
- **CAPEC**: [capec.mitre.org](https://capec.mitre.org/)
- **D3FEND**: [d3fend.mitre.org](https://d3fend.mitre.org/)
- **STRIDE Methodology**: [Microsoft Threat Modeling](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- **STRIDE-CAPEC Mappings**: [Brett Crawley's Research](https://ostering.com/blog/2022/03/07/capec-stride-mapping/)

## 🤝 Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit changes**: `git commit -m 'Add amazing feature'`
4. **Push to branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Contribution Guidelines

- Follow PEP 8 for Python code style
- Add comprehensive logging for new features
- Update documentation and README
- Test with `validate_setup.py` before submitting
- Ensure compatibility with existing automation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **MITRE Corporation** for providing open cybersecurity frameworks
- **Brett Crawley** for comprehensive STRIDE-CAPEC mapping research
- **OSTERING.com** for community-driven threat modeling resources
- **Cybersecurity community** for continuous framework development

## 📞 Support

- **Issues**: Report bugs and request features via GitHub Issues
- **Documentation**: Check this README and inline code comments
- **Community**: Join cybersecurity forums for discussions
- **Updates**: Watch the repository for latest enhancements

---

**Last Updated**: August 18, 2025 | **Version**: 2.0 | **Maintainer**: ellipse2v