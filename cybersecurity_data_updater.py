#!/usr/bin/env python3
"""
Automatic Cybersecurity Data Mapping Update Script
Sources: MITRE ATT&CK, CAPEC, D3FEND, and community mappings

Features:
- Official STRIDE to CAPEC mappings based on community research
- Real-time data fetching from official sources
- Consolidated threat modeling framework mapping

Author: ellipse2v
Date: 2025-08-18
"""

import json
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
import os
import logging
from typing import Dict, List, Any, Set
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cybersec_update.log'),
        logging.StreamHandler()
    ]
)

class CybersecurityDataUpdater:
    """
    Class to fetch and maintain cybersecurity framework data with proper STRIDE-CAPEC mappings
    """
    
    def __init__(self, output_dir: str = "cybersec_data"):
        self.output_dir = output_dir
        self.ensure_output_dir()
        
        # Official data source URLs
        self.sources = {
            'attack_enterprise': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
            'attack_mobile': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json',
            'attack_ics': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json',
            'capec_stix': 'https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json',
            'd3fend_base': 'https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json'
        }
        
        # Official STRIDE to CAPEC mappings based on community research
        # Source: https://ostering.com/blog/2022/03/07/capec-stride-mapping/
        self.stride_capec_mappings = {
            'Spoofing': {
                'description': 'Identity falsification attacks',
                'capec_ids': [
                    # Content Spoofing
                    'CAPEC-148', 'CAPEC-145', 'CAPEC-218', 'CAPEC-502', 'CAPEC-627', 'CAPEC-628',
                    # Identity Spoofing
                    'CAPEC-151', 'CAPEC-194', 'CAPEC-275', 'CAPEC-543', 'CAPEC-544', 'CAPEC-598', 'CAPEC-633',
                    # Principal Spoof
                    'CAPEC-195', 'CAPEC-587', 'CAPEC-599',
                    # Signature Spoof
                    'CAPEC-473', 'CAPEC-459', 'CAPEC-474', 'CAPEC-475', 'CAPEC-476', 'CAPEC-477', 
                    'CAPEC-479', 'CAPEC-485',
                    # Phishing
                    'CAPEC-89', 'CAPEC-98', 'CAPEC-163', 'CAPEC-164', 'CAPEC-656',
                    # Resource Location Spoofing
                    'CAPEC-154', 'CAPEC-159', 'CAPEC-132', 'CAPEC-38', 'CAPEC-471', 'CAPEC-641',
                    # Cache Poisoning
                    'CAPEC-141', 'CAPEC-51', 'CAPEC-142',
                    # Rogue Location
                    'CAPEC-616', 'CAPEC-505', 'CAPEC-611', 'CAPEC-615', 'CAPEC-617', 'CAPEC-630',
                    'CAPEC-631', 'CAPEC-632', 'CAPEC-667',
                    # Action Spoofing
                    'CAPEC-173', 'CAPEC-103', 'CAPEC-181', 'CAPEC-222', 'CAPEC-501', 'CAPEC-504',
                    'CAPEC-654', 'CAPEC-506',
                    # Human Behavior Manipulation
                    'CAPEC-416', 'CAPEC-407', 'CAPEC-383', 'CAPEC-412', 'CAPEC-413', 'CAPEC-414',
                    'CAPEC-415', 'CAPEC-417', 'CAPEC-418', 'CAPEC-420', 'CAPEC-421', 'CAPEC-422',
                    'CAPEC-423', 'CAPEC-424', 'CAPEC-425', 'CAPEC-426', 'CAPEC-427', 'CAPEC-428',
                    'CAPEC-429', 'CAPEC-433', 'CAPEC-434', 'CAPEC-435',
                    # API Manipulation
                    'CAPEC-389'
                ]
            },
            'Tampering': {
                'description': 'Data or system integrity violations',
                'capec_ids': [
                    # Data Structure Manipulation
                    'CAPEC-271', 'CAPEC-267', 'CAPEC-39', 'CAPEC-75', 'CAPEC-123', 'CAPEC-153',
                    'CAPEC-272', 'CAPEC-273', 'CAPEC-74', 'CAPEC-221', 'CAPEC-459',
                    # File System Attacks
                    'CAPEC-132', 'CAPEC-29', 'CAPEC-653', 'CAPEC-635', 'CAPEC-649', 'CAPEC-471',
                    'CAPEC-204', 'CAPEC-17', 'CAPEC-649',
                    # Code Injection
                    'CAPEC-242', 'CAPEC-23', 'CAPEC-250', 'CAPEC-77', 'CAPEC-245', 'CAPEC-83',
                    'CAPEC-85', 'CAPEC-89', 'CAPEC-86', 'CAPEC-113', 'CAPEC-152', 'CAPEC-263',
                    'CAPEC-81', 'CAPEC-78', 'CAPEC-146', 'CAPEC-248', 'CAPEC-13',
                    # Hardware/Firmware
                    'CAPEC-522', 'CAPEC-439', 'CAPEC-440', 'CAPEC-441', 'CAPEC-636', 'CAPEC-637',
                    'CAPEC-638', 'CAPEC-562'
                ]
            },
            'Repudiation': {
                'description': 'Denial of actions or hiding evidence',
                'capec_ids': [
                    # Log Manipulation
                    'CAPEC-268', 'CAPEC-93', 'CAPEC-93', 'CAPEC-268',
                    # Evidence Elimination
                    'CAPEC-578', 'CAPEC-205', 'CAPEC-550', 'CAPEC-97',
                    # Timestamp Manipulation
                    'CAPEC-649', 'CAPEC-26'
                ]
            },
            'Information Disclosure': {
                'description': 'Unauthorized information access or leakage',
                'capec_ids': [
                    # Data Interception
                    'CAPEC-117', 'CAPEC-157', 'CAPEC-158', 'CAPEC-609', 'CAPEC-610', 'CAPEC-612',
                    'CAPEC-613', 'CAPEC-614', 'CAPEC-651', 'CAPEC-651',
                    # Memory Attacks
                    'CAPEC-124', 'CAPEC-134', 'CAPEC-233', 'CAPEC-116', 'CAPEC-37', 'CAPEC-203',
                    # Side Channel Attacks
                    'CAPEC-189', 'CAPEC-188', 'CAPEC-651', 'CAPEC-189',
                    # Application Layer
                    'CAPEC-208', 'CAPEC-224', 'CAPEC-95', 'CAPEC-116', 'CAPEC-37', 'CAPEC-118',
                    'CAPEC-224', 'CAPEC-116', 'CAPEC-95',
                    # Credential Harvesting
                    'CAPEC-509', 'CAPEC-560', 'CAPEC-560', 'CAPEC-509'
                ]
            },
            'Denial of Service': {
                'description': 'Service availability attacks',
                'capec_ids': [
                    # Resource Exhaustion
                    'CAPEC-119', 'CAPEC-125', 'CAPEC-130', 'CAPEC-131', 'CAPEC-147', 'CAPEC-229',
                    'CAPEC-230', 'CAPEC-231', 'CAPEC-482', 'CAPEC-486', 'CAPEC-487', 'CAPEC-488',
                    'CAPEC-489', 'CAPEC-490', 'CAPEC-491', 'CAPEC-492', 'CAPEC-493', 'CAPEC-494',
                    'CAPEC-495', 'CAPEC-496', 'CAPEC-497', 'CAPEC-498', 'CAPEC-499',
                    # Network Layer DoS
                    'CAPEC-21', 'CAPEC-482', 'CAPEC-486', 'CAPEC-487', 'CAPEC-488', 'CAPEC-489',
                    'CAPEC-490', 'CAPEC-491', 'CAPEC-492', 'CAPEC-493', 'CAPEC-494', 'CAPEC-495',
                    'CAPEC-496', 'CAPEC-497', 'CAPEC-498', 'CAPEC-499',
                    # Application Layer DoS
                    'CAPEC-147', 'CAPEC-229', 'CAPEC-230', 'CAPEC-231',
                    # Physical DoS
                    'CAPEC-599', 'CAPEC-600', 'CAPEC-601', 'CAPEC-602', 'CAPEC-603', 'CAPEC-604',
                    'CAPEC-605', 'CAPEC-606', 'CAPEC-607', 'CAPEC-608'
                ]
            },
            'Elevation of Privilege': {
                'description': 'Unauthorized access escalation',
                'capec_ids': [
                    # Access Control Bypass
                    'CAPEC-122', 'CAPEC-58', 'CAPEC-180', 'CAPEC-21', 'CAPEC-122', 'CAPEC-207',
                    'CAPEC-122', 'CAPEC-207',
                    # Authentication Bypass
                    'CAPEC-36', 'CAPEC-36', 'CAPEC-560', 'CAPEC-16', 'CAPEC-554', 'CAPEC-593',
                    # Privilege Escalation
                    'CAPEC-233', 'CAPEC-69', 'CAPEC-40', 'CAPEC-104', 'CAPEC-233', 'CAPEC-69',
                    'CAPEC-40', 'CAPEC-104',
                    # Session Management
                    'CAPEC-21', 'CAPEC-21', 'CAPEC-102', 'CAPEC-102'
                ]
            }
        }
        
        # STRIDE category descriptions
        self.stride_categories = {
            'S': 'Spoofing',
            'T': 'Tampering', 
            'R': 'Repudiation',
            'I': 'Information Disclosure',
            'D': 'Denial of Service',
            'E': 'Elevation of Privilege'
        }
        
    def ensure_output_dir(self):
        """Create output directory if it doesn't exist"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            logging.info(f"Directory created: {self.output_dir}")
    
    def download_with_retry(self, url: str, max_retries: int = 3) -> Dict[str, Any]:
        """
        Download JSON file with automatic retry
        """
        for attempt in range(max_retries):
            try:
                logging.info(f"Downloading: {url} (attempt {attempt + 1})")
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                logging.warning(f"Attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    logging.error(f"Permanent failure for {url}")
                    raise
    
    def fetch_attack_data(self) -> Dict[str, Any]:
        """
        Fetch MITRE ATT&CK data (STIX format)
        """
        logging.info("Fetching MITRE ATT&CK data...")
        
        attack_data = {}
        for domain, url in self.sources.items():
            if 'attack' in domain:
                try:
                    data = self.download_with_retry(url)
                    attack_data[domain] = data
                    
                    # Local save
                    filename = f"{self.output_dir}/{domain}_raw.json"
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    logging.info(f"Data saved: {filename}")
                    
                except Exception as e:
                    logging.error(f"Error for {domain}: {e}")
        
        return attack_data
    
    def fetch_capec_data(self) -> Dict[str, Any]:
        """
        Fetch CAPEC data (STIX format)
        """
        logging.info("Fetching CAPEC data...")
        
        try:
            capec_data = self.download_with_retry(self.sources['capec_stix'])
            
            # Local save
            filename = f"{self.output_dir}/capec_raw.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(capec_data, f, indent=2, ensure_ascii=False)
            logging.info(f"CAPEC data saved: {filename}")
            
            return capec_data
            
        except Exception as e:
            logging.error(f"CAPEC error: {e}")
            return {}
    
    def fetch_d3fend_data(self) -> Dict[str, Any]:
        """
        Fetch D3FEND data (if available)
        """
        logging.info("Fetching D3FEND data...")
        
        try:
            # Note: D3FEND API may be limited or require authentication
            d3fend_data = self.download_with_retry(self.sources['d3fend_base'])
            
            # Local save
            filename = f"{self.output_dir}/d3fend_raw.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(d3fend_data, f, indent=2, ensure_ascii=False)
            logging.info(f"D3FEND data saved: {filename}")
            
            return d3fend_data
            
        except Exception as e:
            logging.warning(f"D3FEND not available via API: {e}")
            return {}
    
    def parse_attack_techniques(self, attack_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse ATT&CK techniques from STIX data
        """
        techniques = []
        
        for domain, data in attack_data.items():
            if 'objects' in data:
                for obj in data['objects']:
                    if obj.get('type') == 'attack-pattern':
                        technique = {
                            'id': obj.get('external_references', [{}])[0].get('external_id', ''),
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'domain': domain,
                            'tactics': [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])],
                            'stix_id': obj.get('id', ''),
                            'created': obj.get('created', ''),
                            'modified': obj.get('modified', ''),
                            'external_references': obj.get('external_references', [])
                        }
                        techniques.append(technique)
        
        return techniques
    
    def parse_attack_mitigations(self, attack_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse ATT&CK mitigations from STIX data
        """
        mitigations = []
        
        for domain, data in attack_data.items():
            if 'objects' in data:
                for obj in data['objects']:
                    if obj.get('type') == 'course-of-action':
                        mitigation = {
                            'id': obj.get('external_references', [{}])[0].get('external_id', ''),
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'domain': domain,
                            'stix_id': obj.get('id', ''),
                            'created': obj.get('created', ''),
                            'modified': obj.get('modified', ''),
                            'external_references': obj.get('external_references', [])
                        }
                        mitigations.append(mitigation)
        
        return mitigations
    
    def parse_capec_patterns(self, capec_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse CAPEC patterns from STIX data
        """
        patterns = []
        
        if 'objects' in capec_data:
            for obj in capec_data['objects']:
                if obj.get('type') == 'attack-pattern':
                    # Extract CAPEC ID from external references
                    capec_id = ''
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'capec':
                            capec_id = ref.get('external_id', '')
                            break
                    
                    pattern = {
                        'id': capec_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'stix_id': obj.get('id', ''),
                        'created': obj.get('created', ''),
                        'modified': obj.get('modified', ''),
                        'external_references': obj.get('external_references', [])
                    }
                    patterns.append(pattern)
        
        return patterns
    
    def create_stride_mapping_with_real_data(self, techniques: List[Dict], 
                                           patterns: List[Dict]) -> Dict[str, Any]:
        """
        Create STRIDE mapping using official CAPEC mappings and real data
        """
        logging.info("Creating STRIDE mapping with official data...")
        
        # Create index of CAPEC patterns by ID for quick lookup
        capec_by_id = {pattern['id']: pattern for pattern in patterns if pattern['id']}
        
        stride_mapping = {}
        
        for category, mapping_info in self.stride_capec_mappings.items():
            stride_mapping[category] = {
                'description': mapping_info['description'],
                'capec_patterns': [],
                'capec_count': 0,
                'attack_techniques': [],
                'mapping_source': 'Official community mapping (ostering.com)'
            }
            
            # Map CAPEC patterns using official mappings
            found_capec_ids = set()
            for capec_id in mapping_info['capec_ids']:
                if capec_id in capec_by_id:
                    pattern = capec_by_id[capec_id]
                    stride_mapping[category]['capec_patterns'].append({
                        'id': pattern['id'],
                        'name': pattern['name'],
                        'description': pattern['description'][:200] + '...' if len(pattern['description']) > 200 else pattern['description']
                    })
                    found_capec_ids.add(capec_id)
            
            stride_mapping[category]['capec_count'] = len(stride_mapping[category]['capec_patterns'])
            
            # Map ATT&CK techniques by analyzing descriptions for STRIDE-related keywords
            stride_keywords = {
                'Spoofing': ['spoof', 'fake', 'impersonat', 'masquerad', 'phish', 'identity', 'forge'],
                'Tampering': ['tamper', 'modify', 'alter', 'corrupt', 'manipulat', 'inject', 'poison'],
                'Repudiation': ['log', 'audit', 'trace', 'evidence', 'timestamp', 'non-repudiation', 'cover'],
                'Information Disclosure': ['disclosure', 'leak', 'exfiltrat', 'credential', 'sensitive', 'data', 'harvest'],
                'Denial of Service': ['denial', 'flood', 'exhaust', 'resource', 'availability', 'crash', 'overwhelm'],
                'Elevation of Privilege': ['privilege', 'escalat', 'admin', 'root', 'elevat', 'bypass', 'unauthorized']
            }
            
            keywords = stride_keywords.get(category, [])
            for tech in techniques:
                desc_lower = (tech.get('description', '') + ' ' + tech.get('name', '')).lower()
                if any(keyword in desc_lower for keyword in keywords):
                    stride_mapping[category]['attack_techniques'].append({
                        'id': tech['id'],
                        'name': tech['name'],
                        'domain': tech['domain'],
                        'tactics': tech.get('tactics', [])
                    })
        
        return stride_mapping
    
    def generate_consolidated_mapping(self) -> Dict[str, Any]:
        """
        Generate consolidated mapping between all frameworks
        """
        logging.info("Generating consolidated mapping...")
        
        # Fetch data
        attack_data = self.fetch_attack_data()
        capec_data = self.fetch_capec_data()
        d3fend_data = self.fetch_d3fend_data()
        
        # Parse data
        techniques = self.parse_attack_techniques(attack_data)
        mitigations = self.parse_attack_mitigations(attack_data)
        capec_patterns = self.parse_capec_patterns(capec_data)
        
        # Create mappings with real data
        stride_mapping = self.create_stride_mapping_with_real_data(techniques, capec_patterns)
        
        # Consolidated mapping
        consolidated = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'version': '2.0',
                'mapping_source': 'Official STRIDE-CAPEC mappings from community research',
                'data_sources': {
                    'attack_techniques_count': len(techniques),
                    'attack_mitigations_count': len(mitigations),
                    'capec_patterns_count': len(capec_patterns),
                    'd3fend_available': bool(d3fend_data),
                    'stride_categories': len(self.stride_capec_mappings)
                }
            },
            'stride_mapping': stride_mapping,
            'framework_stats': {
                'total_capec_mapped': sum(len(category['capec_patterns']) for category in stride_mapping.values()),
                'total_attack_mapped': sum(len(category['attack_techniques']) for category in stride_mapping.values()),
                'coverage_by_category': {
                    category: {
                        'capec_count': len(data['capec_patterns']),
                        'attack_count': len(data['attack_techniques'])
                    } for category, data in stride_mapping.items()
                }
            },
            'sample_data': {
                'attack_techniques': techniques[:10],  # Limited for size
                'attack_mitigations': mitigations[:10],
                'capec_patterns': capec_patterns[:10]
            }
        }
        
        # Save consolidated mapping
        output_file = f"{self.output_dir}/consolidated_mapping.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(consolidated, f, indent=2, ensure_ascii=False)
        
        logging.info(f"Consolidated mapping saved: {output_file}")
        return consolidated
    
    def generate_html_report(self, mapping_data: Dict[str, Any]):
        """
        Generate updated HTML report with real data
        """
        logging.info("Generating HTML report...")
        
        # Calculate statistics
        total_capec = mapping_data['framework_stats']['total_capec_mapped']
        total_attack = mapping_data['framework_stats']['total_attack_mapped']
        
        # Enhanced HTML template
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Cybersecurity Framework Mapping - Updated {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 20px; 
                    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                    color: #333;
                }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ 
                    background: rgba(255,255,255,0.95); 
                    padding: 30px; 
                    border-radius: 15px; 
                    margin-bottom: 20px;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                    backdrop-filter: blur(10px);
                }}
                .header h1 {{ 
                    color: #1e3c72; 
                    margin: 0 0 10px 0; 
                    font-size: 2.5em;
                    text-align: center;
                }}
                .header p {{ 
                    text-align: center; 
                    color: #666; 
                    font-size: 1.1em;
                }}
                .stats {{ 
                    background: rgba(40, 167, 69, 0.9); 
                    color: white;
                    padding: 20px; 
                    border-radius: 10px; 
                    margin: 20px 0;
                    box-shadow: 0 4px 16px rgba(0,0,0,0.2);
                }}
                .stats h2 {{ margin-top: 0; text-align: center; }}
                .stats-grid {{ 
                    display: grid; 
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                    gap: 15px; 
                    margin-top: 15px;
                }}
                .stat-card {{ 
                    background: rgba(255,255,255,0.2); 
                    padding: 15px; 
                    border-radius: 8px; 
                    text-align: center;
                }}
                .stat-number {{ font-size: 2em; font-weight: bold; display: block; }}
                .section {{ 
                    background: rgba(255,255,255,0.95); 
                    margin: 20px 0; 
                    padding: 25px; 
                    border-radius: 10px; 
                    box-shadow: 0 4px 16px rgba(0,0,0,0.1);
                }}
                .section h2 {{ 
                    color: #1e3c72; 
                    border-bottom: 3px solid #2a5298; 
                    padding-bottom: 10px;
                    margin-bottom: 20px;
                }}
                .technique {{ 
                    background: #f8f9fa; 
                    margin: 8px 0; 
                    padding: 12px; 
                    border-radius: 6px; 
                    border-left: 4px solid #007bff;
                    transition: all 0.3s ease;
                }}
                .technique:hover {{ 
                    background: #e9ecef; 
                    transform: translateX(5px);
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                }}
                .capec-pattern {{ 
                    background: #fff3cd; 
                    margin: 8px 0; 
                    padding: 12px; 
                    border-radius: 6px; 
                    border-left: 4px solid #ffc107;
                    transition: all 0.3s ease;
                }}
                .capec-pattern:hover {{ 
                    background: #ffeaa7; 
                    transform: translateX(5px);
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                }}
                .category-grid {{ 
                    display: grid; 
                    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); 
                    gap: 20px; 
                    margin: 20px 0;
                }}
                .category-card {{ 
                    background: rgba(255,255,255,0.95); 
                    border-radius: 10px; 
                    padding: 20px; 
                    box-shadow: 0 4px 16px rgba(0,0,0,0.1);
                }}
                .category-header {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white; 
                    padding: 15px; 
                    border-radius: 8px; 
                    margin-bottom: 15px;
                    text-align: center;
                }}
                .count-badge {{ 
                    background: #dc3545; 
                    color: white; 
                    padding: 4px 8px; 
                    border-radius: 12px; 
                    font-size: 0.8em; 
                    font-weight: bold;
                }}
                .expand-button {{
                    background: #007bff;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 0.9em;
                    margin-top: 10px;
                    transition: all 0.3s ease;
                }}
                .expand-button:hover {{
                    background: #0056b3;
                    transform: translateY(-2px);
                }}
                .hidden-item {{
                    display: none;
                }}
                .expanded {{
                    transition: max-height 0.3s ease;
                }}
                .footer {{ 
                    background: rgba(255,255,255,0.95); 
                    padding: 20px; 
                    border-radius: 10px; 
                    text-align: center; 
                    margin-top: 30px;
                }}
                .footer a {{ color: #007bff; text-decoration: none; }}
                .footer a:hover {{ text-decoration: underline; }}
                @media (max-width: 768px) {{
                    .stats-grid {{ grid-template-columns: 1fr; }}
                    .category-grid {{ grid-template-columns: 1fr; }}
                    .header h1 {{ font-size: 2em; }}
                }}
            </style>
            <script>
                function toggleItems(category, type) {{
                    const container = document.getElementById(category + '_' + type + '_container');
                    const button = document.getElementById(category + '_' + type + '_btn');
                    
                    if (container.classList.contains('expanded')) {{
                        // Réduire : masquer les éléments supplémentaires et réduire la hauteur
                        container.classList.remove('expanded');
                        container.style.maxHeight = '200px';
                        const hiddenItems = container.querySelectorAll('.hidden-item');
                        hiddenItems.forEach(item => item.style.display = 'none');
                        button.textContent = button.textContent.replace('Masquer', 'Voir tous');
                    }} else {{
                        // Étendre : afficher tous les éléments et augmenter la hauteur
                        container.classList.add('expanded');
                        container.style.maxHeight = '400px';
                        const hiddenItems = container.querySelectorAll('.hidden-item');
                        hiddenItems.forEach(item => item.style.display = 'block');
                        button.textContent = button.textContent.replace('Voir tous', 'Masquer');
                    }}
                }}
            </script>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Cybersecurity Framework Mapping</h1>
                    <p>Official data automatically updated from authoritative sources</p>
                    <p><strong>Last update:</strong> {mapping_data['metadata']['generated_at']}</p>
                    <p><strong>Version:</strong> {mapping_data['metadata']['version']} | <strong>Source:</strong> {mapping_data['metadata']['mapping_source']}</p>
                </div>
                
                <div class="stats">
                    <h2>📊 Data Statistics</h2>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <span class="stat-number">{mapping_data['metadata']['data_sources']['attack_techniques_count']}</span>
                            <span>ATT&CK Techniques</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-number">{mapping_data['metadata']['data_sources']['capec_patterns_count']}</span>
                            <span>CAPEC Patterns</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-number">{total_capec}</span>
                            <span>STRIDE-CAPEC Mappings</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-number">{total_attack}</span>
                            <span>STRIDE-ATT&CK Mappings</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-number">{mapping_data['metadata']['data_sources']['attack_mitigations_count']}</span>
                            <span>ATT&CK Mitigations</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-number">{'✅' if mapping_data['metadata']['data_sources']['d3fend_available'] else '❌'}</span>
                            <span>D3FEND Available</span>
                        </div>
                    </div>
                </div>
        """
        
        # Add STRIDE category grid
        html_template += """
        <div class="section">
            <h2>🎯 STRIDE Threat Categories</h2>
            <div class="category-grid">
        """
        
        # Add each STRIDE category as a card
        for category, data in mapping_data['stride_mapping'].items():
            capec_count = len(data['capec_patterns'])
            attack_count = len(data['attack_techniques'])
            category_id = category.replace(' ', '_')
            
            # Build CAPEC patterns HTML (tous dans le même conteneur)
            capec_all_html = ""
            for i, p in enumerate(data['capec_patterns']):
                css_class = 'capec-pattern' if i < 10 else 'capec-pattern hidden-item'
                capec_all_html += f'<div class="{css_class}"><strong>{p["id"]}</strong>: {p["name"]}</div>'
            
            # Build ATT&CK techniques HTML (tous dans le même conteneur)
            attack_all_html = ""
            for i, t in enumerate(data['attack_techniques']):
                css_class = 'technique' if i < 8 else 'technique hidden-item'
                attack_all_html += f'<div class="{css_class}"><strong>{t["id"]}</strong>: {t["name"]} <em>({t["domain"]})</em></div>'
            
            # Build buttons separately
            capec_button = f'<button id="{category_id}_capec_btn" class="expand-button" onclick="toggleItems(\'{category_id}\', \'capec\')">Voir tous ({capec_count - 10} restants)</button>' if capec_count > 10 else ''
            attack_button = f'<button id="{category_id}_attack_btn" class="expand-button" onclick="toggleItems(\'{category_id}\', \'attack\')">Voir tous ({attack_count - 8} restants)</button>' if attack_count > 8 else ''
            
            html_template += f"""
                        <div class="category-card">
                            <div class="category-header">
                                <h3>{category}</h3>
                                <p>{data['description']}</p>
                            </div>
                            
                            <h4>CAPEC Patterns <span class="count-badge">{capec_count}</span></h4>
                            <div id="{category_id}_capec_container" style="max-height: 200px; overflow-y: auto; transition: max-height 0.3s ease;">
                                {capec_all_html}
                            </div>
                            {capec_button}
                            
                            <h4 style="margin-top: 20px;">ATT&CK Techniques <span class="count-badge">{attack_count}</span></h4>
                            <div id="{category_id}_attack_container" style="max-height: 200px; overflow-y: auto; transition: max-height 0.3s ease;">
                                {attack_all_html}
                            </div>
                            {attack_button}
                        </div>
            """
        
        html_template += """
                    </div>
                </div>
        """
        
        # Add coverage analysis section
        html_template += f"""
                <div class="section">
                    <h2>📈 Coverage Analysis</h2>
                    <div class="stats-grid">
        """
        
        for category, stats in mapping_data['framework_stats']['coverage_by_category'].items():
            html_template += f"""
                        <div class="stat-card" style="background: #f8f9fa; color: #333; border: 1px solid #dee2e6;">
                            <h4 style="margin-top: 0; color: #1e3c72;">{category}</h4>
                            <div><strong>{stats['capec_count']}</strong> CAPEC patterns</div>
                            <div><strong>{stats['attack_count']}</strong> ATT&CK techniques</div>
                        </div>
            """
        
        html_template += """
                    </div>
                </div>
        """
        
        # Add automation and sources section
        html_template += f"""
                <div class="section">
                    <h2>🔄 Data Sources & Automation</h2>
                    <p>This report is automatically generated from official cybersecurity framework sources:</p>
                    <ul style="line-height: 1.8;">
                        <li><strong>MITRE ATT&CK:</strong> <a href="https://github.com/mitre-attack/attack-stix-data" target="_blank">Official STIX Data Repository</a></li>
                        <li><strong>CAPEC:</strong> <a href="https://github.com/mitre/cti" target="_blank">MITRE CTI Repository</a></li>
                        <li><strong>D3FEND:</strong> Official API (when available)</li>
                        <li><strong>STRIDE-CAPEC Mappings:</strong> <a href="https://ostering.com/blog/2022/03/07/capec-stride-mapping/" target="_blank">Community Research by Brett Crawley</a></li>
                    </ul>
                    
                    <div style="background: #e3f2fd; padding: 15px; border-radius: 8px; margin-top: 20px;">
                        <h4 style="margin-top: 0; color: #1565c0;">🤖 Automation Features</h4>
                        <ul style="margin-bottom: 0;">
                            <li>Daily automatic updates from official sources</li>
                            <li>Real-time CAPEC pattern integration</li>
                            <li>Official STRIDE threat category mappings</li>
                            <li>Cross-framework correlation analysis</li>
                            <li>Comprehensive coverage statistics</li>
                        </ul>
                    </div>
                </div>
                
                <div class="footer">
                    <p>Generated by <strong>Cybersecurity Data Updater v{mapping_data['metadata']['version']}</strong></p>
                    <p>Run the Python script to update this data | <a href="consolidated_mapping.json">Download Raw JSON Data</a></p>
                    <p>Last successful update: <strong>{mapping_data['metadata']['generated_at']}</strong></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Save report
        report_file = f"{self.output_dir}/cybersec_report.html"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        logging.info(f"Enhanced HTML report generated: {report_file}")

def main():
    """
    Main function
    """
    print("🔄 Starting cybersecurity data update...")
    
    updater = CybersecurityDataUpdater()
    
    try:
        # Generate consolidated mapping
        mapping_data = updater.generate_consolidated_mapping()
        
        # Generate HTML report
        updater.generate_html_report(mapping_data)
        
        print(f"✅ Update completed! Files in '{updater.output_dir}/'")
        print(f"📊 {mapping_data['metadata']['data_sources']['attack_techniques_count']} ATT&CK techniques retrieved")
        print(f"📊 {mapping_data['metadata']['data_sources']['capec_patterns_count']} CAPEC patterns retrieved")
        print(f"🎯 {mapping_data['framework_stats']['total_capec_mapped']} STRIDE-CAPEC mappings created")
        print(f"🎯 {mapping_data['framework_stats']['total_attack_mapped']} STRIDE-ATT&CK mappings created")
        print(f"🌐 Open {updater.output_dir}/cybersec_report.html to view the report")
        
    except Exception as e:
        logging.error(f"Error during update: {e}")
        raise

if __name__ == "__main__":
    main() 
                    