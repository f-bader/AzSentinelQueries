#!/usr/bin/env python3
"""
Sentinel Analytics Rules Test Framework
This script implements a Test Driven Development approach for Azure Sentinel rules.
"""

import os
import json
import yaml
import time
import glob
import re
from datetime import datetime

from azure.identity import ClientSecretCredential
from azure.mgmt.securityinsight import SecurityInsights
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError

# Environment configuration
SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID")
RESOURCE_GROUP = os.environ.get("RESOURCE_GROUP")
WORKSPACE_NAME = os.environ.get("WORKSPACE_NAME")

# Log ingestion configuration - get these from environment variables for security
ENDPOINT_URI = os.environ.get("ENDPOINT_URI")  # DCE endpoint
DCR_IMMUTABLEID = os.environ.get("DCR_IMMUTABLEID")  # Data Collection Rule ID
TENANT_ID = os.environ.get("AZURE_TENANT_ID")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")

class SentinelTestFramework:
    def __init__(self):
        # Set up authentication
        self.credential = ClientSecretCredential(
            tenant_id=TENANT_ID,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET
        )
        
        # Set up Sentinel client
        self.sentinel_client = SecurityInsights(
            self.credential,
            SUBSCRIPTION_ID
        )
        
        # Set up Logs Ingestion client
        self.logs_client = LogsIngestionClient(
            endpoint=ENDPOINT_URI,
            credential=self.credential,
            logging_enable=True
        )
        
        print("Initialized Sentinel Test Framework")

    def find_test_files(self):
        """Find all test YAML files in the tests directory"""
        return glob.glob("tests/*.yaml")

    def load_test_config(self, test_file):
        """Load test configuration from YAML file"""
        try:
            with open(test_file, 'r') as file:
                config = yaml.safe_load(file)
                print(f"Loaded test configuration: {json.dumps(config, indent=2)}")
                return config
        except Exception as e:
            print(f"Error loading test file {test_file}: {e}")
            print(f"Current directory: {os.getcwd()}")
            print(f"Files in tests directory: {os.listdir('tests') if os.path.exists('tests') else 'Directory not found'}")
            raise

    def load_production_rule(self, rule_file):
        """Load production rule definition from YAML file"""
        try:
            with open(f"custom/{rule_file}", 'r') as file:
                rule_def = yaml.safe_load(file)
                print(f"Loaded rule definition: {json.dumps(rule_def, indent=2)}")
                return rule_def
        except Exception as e:
            print(f"Error loading rule file {rule_file}: {e}")
            print(f"Current directory: {os.getcwd()}")
            print(f"Files in custom directory: {os.listdir('custom') if os.path.exists('custom') else 'Directory not found'}")
            raise

    def replace_table_in_query(self, query, test_table):
        
        lines = query.split('\n')
        if lines and lines[0].strip().startswith('Event'):
            print(f"Found starting table 'Event', replacing with '{test_table}'")
            lines[0] = lines[0].replace('Event', test_table, 1)
            return '\n'.join(lines)
            
        # More generic approach for other queries
        common_patterns = [
            r'^\s*(\w+)', # First word in the query is often the table
            r'from\s+(\w+)',  # from Table
            r'join\s+(\w+)',  # join Table
            r'(\w+)\s*\|',  # Table | where ...
        ]
        
        for pattern in common_patterns:
            matches = re.findall(pattern, query, re.MULTILINE)
            if matches:
                # Use the first match (the first table name in the query)
                original_table = matches[0]
                if original_table.lower() not in ['where', 'project', 'extend', 'summarize', 'count', 'take', 'top']:
                    print(f"Detected original table: {original_table}")
                    pattern = r'\b' + re.escape(original_table) + r'\b'
                    # Replace only the first occurrence to avoid replacing table aliases
                    modified = re.sub(pattern, test_table, query, count=1)
                    return modified
        
        # If we can't confidently identify the table, return the original query
        print("WARNING: Could not detect table name in query, returning original")
        return query

    def convert_duration_to_iso8601(self, duration_str):
        """Convert duration strings like '30m', '1h', '1d' to ISO8601 format."""
        if not duration_str or not isinstance(duration_str, str):
            return duration_str
            
        # Already in ISO format
        if duration_str.startswith('P') or duration_str.startswith('PT'):
            return duration_str
            
        # Handle minute format: 30m -> PT30M
        if re.match(r'^\d+m$', duration_str):
            minutes = re.match(r'^(\d+)m$', duration_str).group(1)
            return f"PT{minutes}M"
            
        # Handle hour format: 1h -> PT1H
        if re.match(r'^\d+h$', duration_str):
            hours = re.match(r'^(\d+)h$', duration_str).group(1)
            return f"PT{hours}H"
            
        # Handle day format: 1d -> P1D
        if re.match(r'^\d+d$', duration_str):
            days = re.match(r'^(\d+)d$', duration_str).group(1)
            return f"P{days}D"
            
        # Return original if no match
        return duration_str
        
    def convert_trigger_operator(self, operator):
        """Convert shorthand trigger operators to full names."""
        operator_map = {
            "gt": "GreaterThan",
            "lt": "LessThan",
            "eq": "Equal",
            "ne": "NotEqual"
        }
        
        return operator_map.get(operator, operator)

    def ingest_test_data(self, table_name, data_file):
        test_data = ""
        with open(f"test_data/{data_file}", 'r') as file:
            test_data = json.load(file)
        
        if isinstance(test_data, dict):
            if 'TimeGenerated' not in test_data:
                test_data['TimeGenerated'] = datetime.utcnow().isoformat()
            test_data = [test_data]
        elif isinstance(test_data, list):
            for entry in test_data:
                if 'TimeGenerated' not in entry:
                    entry['TimeGenerated'] = datetime.utcnow().isoformat()
        
        print(f"Ingesting test data into table: {table_name}")
        
        stream_name = f"Custom-{table_name}"
        
        try:
            self.logs_client.upload(
                rule_id=DCR_IMMUTABLEID,
                stream_name=stream_name,
                logs=test_data
            )
            print(f"Successfully ingested test data from {data_file} into {table_name}")
            print("Waiting for logs to be processed")
            time.sleep(60) 
            
        except HttpResponseError as e:
            print(f"Failed to ingest test data: {e}")
            raise

    def clone_rule_for_testing(self, rule_def, test_table):
        """Create a clone of the production rule pointing to test table"""
        # Create modified rule with standardized field names for Sentinel API
        test_rule = {}
        
        # Map from Detection as Code format to Sentinel API expected format
        # First, copy all fields from the original definition
        for key, value in rule_def.items():
            test_rule[key] = value
            
        # Handle ID field - use original if present or generate a new one
        if 'id' in rule_def:
            # Add timestamp to ensure uniqueness
            test_rule['id'] = f"test_{rule_def['id']}_{int(time.time())}"
            #test_rule['id'] = f"test_{rule_def['id']}"
        else:
            test_rule['id'] = f"test_rule_{int(time.time())}"
            
        # Handle display name field
        if 'name' in rule_def:
            # Your rule uses 'name' for display name
            test_rule['displayName'] = f"TEST - {rule_def['name']}"
        elif 'displayName' in rule_def:
            test_rule['displayName'] = f"TEST - {rule_def['displayName']}"
        else:
            test_rule['displayName'] = f"TEST - Generated Rule {int(time.time())}"
        
        # Update query to use test table
        if 'query' in rule_def:
            modified_query = self.replace_table_in_query(rule_def['query'], test_table)
            test_rule['query'] = modified_query
        else:
            print("ERROR: Could not find 'query' field in rule definition")
            raise ValueError("Rule definition must contain a query field")
            
        # Convert duration fields to ISO8601 format
        duration_fields = ['queryFrequency', 'queryPeriod', 'suppressionDuration']
        for field in duration_fields:
            if field in test_rule:
                test_rule[field] = self.convert_duration_to_iso8601(test_rule[field])
                print(f"Converted {field}: {rule_def.get(field, '')} -> {test_rule[field]}")
                
        # Convert trigger operator if needed
        if 'triggerOperator' in test_rule:
            test_rule['triggerOperator'] = self.convert_trigger_operator(test_rule['triggerOperator'])
            print(f"Trigger operator: {test_rule['triggerOperator']}")
            
        # Handle incident configuration lookback duration
        if 'incidentConfiguration' in test_rule and 'groupingConfiguration' in test_rule['incidentConfiguration']:
            if 'lookbackDuration' in test_rule['incidentConfiguration']['groupingConfiguration']:
                lookback = test_rule['incidentConfiguration']['groupingConfiguration']['lookbackDuration']
                test_rule['incidentConfiguration']['groupingConfiguration']['lookbackDuration'] = self.convert_duration_to_iso8601(lookback)
                
        # Print the mapped fields for debugging
        print(f"Original 'name': {rule_def.get('name')}")
        print(f"Mapped 'displayName': {test_rule.get('displayName')}")
        print(f"Original 'id': {rule_def.get('id')}")
        print(f"Mapped 'id': {test_rule.get('id')}")
        
        # Ensure all required fields are present for creating the rule
        # Standard fields required by the Sentinel API
        required_fields = [
            'displayName', 'query', 'queryFrequency', 'queryPeriod',
            'severity', 'triggerOperator', 'triggerThreshold'
        ]
        
        # Set defaults for missing fields if needed
        defaults = {
            'queryFrequency': 'PT1H',  # 1 hour
            'queryPeriod': 'PT1H',     # 1 hour
            'severity': 'Medium',
            'triggerOperator': 'GreaterThan',
            'triggerThreshold': 0,
            'enabled': True
        }
        
        for field, default_value in defaults.items():
            if field not in test_rule:
                print(f"Adding default value for missing field '{field}': {default_value}")
                test_rule[field] = default_value
        
        # Check if any required fields are still missing
        missing_fields = [field for field in required_fields if field not in test_rule]
        if missing_fields:
            print(f"ERROR: Still missing required fields for rule creation: {missing_fields}")
            raise ValueError(f"Cannot create rule without required fields: {missing_fields}")
            
        # Create/update the test rule
        try:
            # Check available attributes in sentinel_client to help debug
            print(f"Available client attributes: {dir(self.sentinel_client)}")
            
            # Try different method names based on SDK version
            if hasattr(self.sentinel_client, 'scheduled_analytics_rules'):
                response = self.sentinel_client.scheduled_analytics_rules.create_or_update(
                    resource_group_name=RESOURCE_GROUP,
                    workspace_name=WORKSPACE_NAME,
                    rule_id=test_rule['id'],
                    scheduled_analytics_rule=test_rule
                )
            elif hasattr(self.sentinel_client, 'alert_rules'):
                response = self.sentinel_client.alert_rules.create_or_update(
                    resource_group_name=RESOURCE_GROUP,
                    workspace_name=WORKSPACE_NAME,
                    rule_id=test_rule['id'],
                    alert_rule=test_rule
                )
            elif hasattr(self.sentinel_client, 'alert_rule_templates'):
                # Some versions use alert_rule_templates instead
                response = self.sentinel_client.alert_rule_templates.create_or_update(
                    resource_group_name=RESOURCE_GROUP,
                    workspace_name=WORKSPACE_NAME,
                    rule_id=test_rule['id'],
                    alert_rule=test_rule
                )
            else:
                # Try using direct REST API call as fallback
                print("Could not find appropriate SDK method, attempting direct API call")
                from azure.mgmt.resource import ResourceManagementClient
                import requests
                
                # Get the access token for direct API call
                token = self.credential.get_token("https://management.azure.com/.default").token
                api_version = "2022-09-01-preview"  # Adjust version as needed
                
                # Construct the URL for the create/update action
                url = (
                    f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
                    f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
                    f"/providers/Microsoft.SecurityInsights/alertRules/{test_rule['id']}?api-version={api_version}"
                )
                
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
                
                response = requests.put(url, headers=headers, json=test_rule)
                
                if response.status_code >= 400:
                    print(f"Error creating rule via direct API: {response.status_code} - {response.text}")
                    raise HttpResponseError(response=response)
            
            print(f"Successfully created/updated test rule {test_rule['id']}")
            return test_rule['id']
        except Exception as e:
            print(f"Error creating test rule: {e}")
            # Print more details about what was sent
            print(f"Rule creation payload: {json.dumps({k: v for k, v in test_rule.items() if k != 'query'}, indent=2)}")
            raise

    def run_rule(self, rule_id):
        try:
            if hasattr(self.sentinel_client, 'scheduled_analytics_rules') and hasattr(self.sentinel_client.scheduled_analytics_rules, 'run'):
                self.sentinel_client.scheduled_analytics_rules.run(
                    resource_group_name=RESOURCE_GROUP,
                    workspace_name=WORKSPACE_NAME,
                    rule_id=rule_id
                )
            elif hasattr(self.sentinel_client, 'alert_rules') and hasattr(self.sentinel_client.alert_rules, 'run'):
                self.sentinel_client.alert_rules.run(
                    resource_group_name=RESOURCE_GROUP,
                    workspace_name=WORKSPACE_NAME,
                    rule_id=rule_id
                )
            else:
                print("Using direct API call")
                import requests
                
                token = self.credential.get_token("https://management.azure.com/.default").token
                api_version = "2022-09-01-preview"
                
                url = (
                    f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
                    f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
                    f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}/run?api-version={api_version}"
                )
                
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
                
                response = requests.post(url, headers=headers)
                
                if response.status_code >= 400:
                    print(f"Error running rule via direct API: {response.status_code} - {response.text}")
                    raise HttpResponseError(response=response)
                
            print(f"Triggered execution of rule: {rule_id}")
            print("Waiting for rule to execute")
            time.sleep(60)
            
        except Exception as e:
            print(f"Failed to run rule: {e}")
            raise

    def check_for_alerts(self, rule_id, timeout=120):
        """Check if rule generated any alerts/incidents"""
        print(f"Checking for incidents related to rule: {rule_id}")
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # First try the incidents API
                if hasattr(self.sentinel_client, 'incidents'):
                    incidents = self.sentinel_client.incidents.list(
                        resource_group_name=RESOURCE_GROUP,
                        workspace_name=WORKSPACE_NAME
                    )
                    
                    # Convert iterator to list so we can iterate multiple times
                    incidents_list = list(incidents)
                    
                    if not incidents_list:
                        print("No incidents found yet")
                    else:
                        print(f"Found {len(incidents_list)} incidents, checking for matches")
                        
                    for incident in incidents_list:
                        # Check if incident is related to our test rule
                        if incident.title and rule_id in incident.title:
                            print(f"Found incident from rule {rule_id}: {incident.title}")
                            return True
                        elif hasattr(incident, 'alert_ids') and incident.alert_ids:
                            # Check alert details if incident title doesn't contain rule ID
                            print(f"Checking alert details for incident: {incident.title}")
                            # This would require additional API calls to check alert details
                
                # Alternatively, check the alert API directly
                elif hasattr(self.sentinel_client, 'alerts'):
                    alerts = self.sentinel_client.alerts.list(
                        resource_group_name=RESOURCE_GROUP,
                        workspace_name=WORKSPACE_NAME
                    )
                    
                    alerts_list = list(alerts)
                    
                    if not alerts_list:
                        print("No alerts found yet")
                    else:
                        print(f"Found {len(alerts_list)} alerts, checking for matches")
                        
                    for alert in alerts_list:
                        if alert.alert_display_name and rule_id in alert.alert_display_name:
                            print(f"Found alert from rule {rule_id}: {alert.alert_display_name}")
                            return True
                
                # If neither API is available, try using direct REST API call
                else:
                    # Try direct REST API call
                    import requests
                    token = self.credential.get_token("https://management.azure.com/.default").token
                    api_version = "2022-09-01-preview"
                    
                    # First try incidents
                    incidents_url = (
                        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
                        f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
                        f"/providers/Microsoft.SecurityInsights/incidents?api-version={api_version}"
                    )
                    
                    headers = {
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json"
                    }
                    
                    response = requests.get(incidents_url, headers=headers)
                    
                    if response.status_code == 200:
                        incidents_data = response.json()
                        if 'value' in incidents_data and incidents_data['value']:
                            for incident in incidents_data['value']:
                                if 'properties' in incident and 'title' in incident['properties']:
                                    title = incident['properties']['title']
                                    if rule_id in title:
                                        print(f"Found incident from rule {rule_id}: {title}")
                                        return True
                    else:
                        print(f"Warning: Failed to get incidents via direct API: {response.status_code}")
                
                print("No matching incidents found yet, waiting...")
                time.sleep(15)
                
            except Exception as e:
                print(f"Error checking for incidents: {e}")
                time.sleep(15)
        
        print(f"No matching incidents found after {timeout} seconds")
        return False

    def cleanup_test_rule(self, rule_id):
        """Clean up the test rule after testing"""
        try:
            # Try different method names based on SDK version
            if hasattr(self.sentinel_client, 'scheduled_analytics_rules'):
                self.sentinel_client.scheduled_analytics_rules.delete(
                    resource_group_name=RESOURCE_GROUP,
                    workspace_name=WORKSPACE_NAME,
                    rule_id=rule_id
                )
            elif hasattr(self.sentinel_client, 'alert_rules'):
                self.sentinel_client.alert_rules.delete(
                    resource_group_name=RESOURCE_GROUP,
                    workspace_name=WORKSPACE_NAME,
                    rule_id=rule_id
                )
            else:
                # Try using direct REST API call as fallback
                print("Could not find appropriate SDK method for deleting rule, attempting direct API call")
                from azure.core.exceptions import HttpResponseError
                import requests
                
                # Get the access token for direct API call
                token = self.credential.get_token("https://management.azure.com/.default").token
                api_version = "2022-09-01-preview"  # Adjust version as needed
                
                # Construct the URL for the delete action
                url = (
                    f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
                    f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
                    f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}?api-version={api_version}"
                )
                
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
                
                response = requests.delete(url, headers=headers)
                
                if response.status_code >= 400 and response.status_code != 404:  # Ignore 404 (not found)
                    print(f"Error deleting rule via direct API: {response.status_code} - {response.text}")
                    raise HttpResponseError(response=response)
                
            print(f"Deleted test rule: {rule_id}")
        except Exception as e:
            print(f"Warning: Failed to delete test rule {rule_id}: {e}")
            # Continue execution even if cleanup fails

    def run_tests(self):
        """Run all tests"""
        test_files = self.find_test_files()
        
        if not test_files:
            print("No test files found in the tests directory")
            return
            
        results = {
            "passed": 0,
            "failed": 0,
            "tests": []
        }
        
        for test_file in test_files:
            print(f"\n=== Running test: {test_file} ===")
            test_config = self.load_test_config(test_file)
            
            # Load production rule
            try:
                prod_rule = self.load_production_rule(test_config['production_rule'])
            except Exception as e:
                print(f"Error loading production rule: {e}")
                continue
                
            test_result = {
                "name": test_config['name'],
                "file": test_file,
                "test_cases": []
            }
            
            # Run test cases
            for test_case in test_config['test_cases']:
                print(f"\nRunning test case: {test_case['name']}")
                test_rule_id = None
                
                try:
                    # Clone rule first to be ready before data ingestion
                    test_rule_id = self.clone_rule_for_testing(prod_rule, test_config['test_table'])
                    
                    # Ingest test data
                    self.ingest_test_data(test_config['test_table'], test_case['data_file'])
                    
                    # Run rule
                    self.run_rule(test_rule_id)
                    
                    # Check for alerts
                    found_alert = self.check_for_alerts(test_rule_id)
                    
                    # Evaluate test result
                    expected_alert = test_case['expected_result'] == 'alert'
                    case_passed = found_alert == expected_alert
                    
                    if case_passed:
                        print(f"✅ Test case passed: {test_case['name']}")
                        results["passed"] += 1
                    else:
                        print(f"❌ Test case failed: {test_case['name']}")
                        print(f"   Expected {'an alert' if expected_alert else 'no alert'}, but {'found an alert' if found_alert else 'found no alert'}")
                        results["failed"] += 1
                    
                    test_result["test_cases"].append({
                        "name": test_case['name'],
                        "passed": case_passed,
                        "expected": test_case['expected_result'],
                        "actual": "alert" if found_alert else "no_alert"
                    })
                    
                except Exception as e:
                    print(f"❌ Error running test case: {e}")
                    results["failed"] += 1
                    test_result["test_cases"].append({
                        "name": test_case['name'],
                        "passed": False,
                        "error": str(e)
                    })
                
                finally:
                    # Clean up
                    if test_rule_id:
                        try:
                            self.cleanup_test_rule(test_rule_id)
                        except:
                            print("Warning: Cleanup may have failed")
            
            results["tests"].append(test_result)
        
        # Save test results to file
        with open('test_results.json', 'w') as f:
            json.dump(results, f, indent=2)
            
        # Print summary
        print("\n=== Test Summary ===")
        print(f"Passed: {results['passed']}")
        print(f"Failed: {results['failed']}")
        print(f"Total: {results['passed'] + results['failed']}")
        print(f"Detailed results saved to test_results.json")
        
        # Exit with non-zero code if any tests failed
        if results['failed'] > 0:
            exit(1)


if __name__ == "__main__":

    required_vars = [
        "AZURE_SUBSCRIPTION_ID", "RESOURCE_GROUP", "WORKSPACE_NAME",
        "ENDPOINT_URI", "DCR_IMMUTABLEID", 
        "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"
    ]
    
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        exit(1)
        
    framework = SentinelTestFramework()
    framework.run_tests()
