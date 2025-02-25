#!/usr/bin/env python3
"""
Sentinel Analytics Rules Test Framework
This script implements a Test Driven Development approach for Azure Sentinel rules.
"""

import os
import json
import yaml
import time
import uuid
import glob
import re
from datetime import datetime, timedelta

from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from azure.kusto.data.exceptions import KustoServiceError
from azure.kusto.ingest import QueuedIngestClient, IngestionProperties, FileDescriptor, BlobDescriptor

# Environment configuration
SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID")
RESOURCE_GROUP = os.environ.get("RESOURCE_GROUP")
WORKSPACE_NAME = os.environ.get("WORKSPACE_NAME")
WORKSPACE_ID = os.environ.get("WORKSPACE_ID")  # Needed for Log Analytics ingestion

class SentinelTestFramework:
    def __init__(self):
        self.credential = DefaultAzureCredential()
        self.sentinel_client = SecurityInsights(
            self.credential,
            SUBSCRIPTION_ID
        )
        
        # Set up Kusto client for log ingestion
        cluster = f"https://{WORKSPACE_ID}.ods.opinsights.azure.com"
        kcsb = KustoConnectionStringBuilder.with_azure_token_credential(cluster, self.credential)
        self.kusto_client = KustoClient(kcsb)
        self.ingest_client = QueuedIngestClient(kcsb)

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

    def replace_table_in_query(self, query, original_table, test_table):
        """Replace table reference in KQL query"""
        # This is a simplified approach - in production, consider using proper KQL parsing
        pattern = r'\b' + re.escape(original_table) + r'\b'
        return re.sub(pattern, test_table, query)

    def ingest_test_data(self, table_name, data_file):
        """Ingest test data into the test table"""
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
        
        # Prepare for ingestion
        temp_file = f"/tmp/{uuid.uuid4()}.json"
        with open(temp_file, 'w') as file:
            json.dump(test_data, file)
        
        # Ingest data
        ingestion_props = IngestionProperties(
            database=WORKSPACE_NAME,
            table=table_name,
            data_format="MULTIJSON"
        )
        
        file_descriptor = FileDescriptor(temp_file, 0)
        self.ingest_client.ingest_from_file(file_descriptor, ingestion_props)
        print(f"Ingested test data from {data_file} into {table_name}")
        
        # Clean up
        os.remove(temp_file)
        
        # Allow time for ingestion to complete
        time.sleep(30)  # Adjust based on your environment

    def clone_rule_for_testing(self, rule_def, test_table):
        """Create a clone of the production rule pointing to test table"""
        # Extract the original table name from the query
        # This is simplified; in production, you might need a more robust approach
        query = rule_def.get('query', '')
        
        # Hard part: determining the original table name
        # This is a simplified approach - may need adjustment for complex queries
        table_match = re.search(r'from\s+(\w+)', query, re.IGNORECASE)
        if table_match:
            original_table = table_match.group(1)
            print(f"Detected original table: {original_table}")
        else:
            raise ValueError("Could not detect original table name in query")
        
        # Create modified rule
        test_rule = rule_def.copy()
        test_rule['id'] = f"test_{rule_def['id']}"
        test_rule['displayName'] = f"TEST - {rule_def['displayName']}"
        test_rule['query'] = self.replace_table_in_query(query, original_table, test_table)
        
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
        self.sentinel_client.scheduled_analytics_rules.run(
            resource_group_name=RESOURCE_GROUP,
            workspace_name=WORKSPACE_NAME,
            rule_id=rule_id
        )
        print(f"Triggered execution of rule: {rule_id}")

    def check_for_alerts(self, rule_id, timeout=120):
        """Check if rule generated any alerts/incidents"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            incidents = self.sentinel_client.incidents.list(
                resource_group_name=RESOURCE_GROUP,
                workspace_name=WORKSPACE_NAME
            )
            
            for incident in incidents:
                # Check if incident is related to our test rule
                if incident.title and rule_id in incident.title:
                    print(f"Found incident from rule {rule_id}: {incident.title}")
                    return True
            
            print("No incidents found yet, waiting...")
            time.sleep(10)
        
        return False

    def cleanup_test_rule(self, rule_id):
        """Clean up the test rule after testing"""
        self.sentinel_client.scheduled_analytics_rules.delete(
            resource_group_name=RESOURCE_GROUP,
            workspace_name=WORKSPACE_NAME,
            rule_id=rule_id
        )
        print(f"Deleted test rule: {rule_id}")

    def run_tests(self):
        """Run all tests"""
        test_files = self.find_test_files()
        
        results = {
            "passed": 0,
            "failed": 0,
            "tests": []
        }
        
        for test_file in test_files:
            print(f"\n=== Running test: {test_file} ===")
            test_config = self.load_test_config(test_file)
            
            # Load production rule
            prod_rule = self.load_production_rule(test_config['production_rule'])
            
            test_result = {
                "name": test_config['name'],
                "file": test_file,
                "test_cases": []
            }
            
            # Run test cases
            for test_case in test_config['test_cases']:
                print(f"\nRunning test case: {test_case['name']}")
                
                # Ingest test data
                self.ingest_test_data(test_config['test_table'], test_case['data_file'])
                
                # Clone rule
                test_rule_id = self.clone_rule_for_testing(prod_rule, test_config['test_table'])
                
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
                
                # Clean up
                self.cleanup_test_rule(test_rule_id)
            
            results["tests"].append(test_result)
        
        # Print summary
        print("\n=== Test Summary ===")
        print(f"Passed: {results['passed']}")
        print(f"Failed: {results['failed']}")
        print(f"Total: {results['passed'] + results['failed']}")
        
        # Exit with non-zero code if any tests failed
        if results['failed'] > 0:
            exit(1)


if __name__ == "__main__":
    framework = SentinelTestFramework()
    framework.run_tests()
