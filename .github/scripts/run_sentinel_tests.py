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

from azure.identity import ClientSecretCredential, DefaultAzureCredential
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
        with open(test_file, 'r') as file:
            return yaml.safe_load(file)

    def load_production_rule(self, rule_file):
        """Load production rule definition from YAML file"""
        with open(f"custom/{rule_file}", 'r') as file:
            return yaml.safe_load(file)

    def replace_table_in_query(self, query, test_table):
        """Replace table reference in KQL query"""
        # Identify table pattern in KQL - this approach handles the most common patterns
        # May need refinement for complex queries
        common_patterns = [
            r'(\w+)\s*\|',  # Table | where ...
            r'from\s+(\w+)',  # from Table
            r'join\s+(\w+)',  # join Table
        ]
        
        # Find all potential table names
        tables = []
        for pattern in common_patterns:
            matches = re.finditer(pattern, query, re.IGNORECASE)
            for match in matches:
                tables.append(match.group(1))
        
        # Remove duplicates and common KQL command words that might be mistaken for tables
        exclude_words = ['where', 'project', 'extend', 'summarize', 'count', 'take', 'top', 'limit', 'order', 'sort', 'join']
        tables = [t for t in tables if t.lower() not in exclude_words]
        
        # For simplicity in this example, we'll replace the first identified table
        # In a production system, you might want to confirm with the user or use more sophisticated parsing
        if tables:
            original_table = tables[0]
            print(f"Detected original table: {original_table}")
            pattern = r'\b' + re.escape(original_table) + r'\b'
            return re.sub(pattern, test_table, query)
        else:
            print("WARNING: Could not detect table name in query")
            return query

    def ingest_test_data(self, table_name, data_file):
        """Ingest test data into the test table using proven method"""
        # Load test data
        with open(f"test_data/{data_file}", 'r') as file:
            test_data = json.load(file)
        
        # Ensure test data has a timestamp for the current time
        if isinstance(test_data, dict):
            # Single entry
            if 'TimeGenerated' not in test_data:
                test_data['TimeGenerated'] = datetime.utcnow().isoformat()
            test_data = [test_data]
        elif isinstance(test_data, list):
            # List of entries
            for entry in test_data:
                if 'TimeGenerated' not in entry:
                    entry['TimeGenerated'] = datetime.utcnow().isoformat()
        
        print(f"Ingesting test data into table: {table_name}")
        
        # Use the custom table stream name format
        stream_name = f"Custom-{table_name}"
        
        try:
            # Upload logs
            self.logs_client.upload(
                rule_id=DCR_IMMUTABLEID,
                stream_name=stream_name,
                logs=test_data
            )
            print(f"Successfully ingested test data from {data_file} into {table_name}")
            
            # Allow time for ingestion to complete
            print("Waiting for logs to be processed...")
            time.sleep(60)  # Adjust based on your environment
            
        except HttpResponseError as e:
            print(f"Failed to ingest test data: {e}")
            raise

    def clone_rule_for_testing(self, rule_def, test_table):
        """Create a clone of the production rule pointing to test table"""
        # Create modified rule
        test_rule = rule_def.copy()
        test_rule['id'] = f"test_{rule_def['id']}"
        test_rule['displayName'] = f"TEST - {rule_def['displayName']}"
        
        # Replace table reference in query
        test_rule['query'] = self.replace_table_in_query(rule_def['query'], test_table)
        
        # Create/update the test rule
        response = self.sentinel_client.scheduled_analytics_rules.create_or_update(
            resource_group_name=RESOURCE_GROUP,
            workspace_name=WORKSPACE_NAME,
            rule_id=test_rule['id'],
            scheduled_analytics_rule=test_rule
        )
        
        print(f"Created test rule: {test_rule['id']}")
        return test_rule['id']

    def run_rule(self, rule_id):
        """Manually trigger rule execution"""
        try:
            self.sentinel_client.scheduled_analytics_rules.run(
                resource_group_name=RESOURCE_GROUP,
                workspace_name=WORKSPACE_NAME,
                rule_id=rule_id
            )
            print(f"Triggered execution of rule: {rule_id}")
            
            # Give the rule time to execute
            print("Waiting for rule to execute...")
            time.sleep(60)  # Adjust based on rule complexity
            
        except Exception as e:
            print(f"Failed to run rule: {e}")
            raise

    def check_for_alerts(self, rule_id, timeout=120):
        """Check if rule generated any alerts/incidents"""
        print(f"Checking for incidents related to rule: {rule_id}")
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
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
                        # Implementation depends on specific API structure
                
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
            self.sentinel_client.scheduled_analytics_rules.delete(
                resource_group_name=RESOURCE_GROUP,
                workspace_name=WORKSPACE_NAME,
                rule_id=rule_id
            )
            print(f"Deleted test rule: {rule_id}")
        except Exception as e:
            print(f"Warning: Failed to delete test rule {rule_id}: {e}")

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
    # Check for required environment variables
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
