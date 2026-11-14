import json

with open('docs/audit/evidence/phase2/part2a_results.json', 'r', encoding='utf-8') as f:
    items = json.load(f)

# 1. Update 6.2
for item in items:
    if item.get('item_id') == '6.2':
        item['status'] = 'PASS'
        item['response'] = 'total=106, planned=47, na=59 (crawled target baseline); planned=46, na=60 (with 1 manual override)'
        item['actual'] = 'Instances: 106 total, 47 planned, 59 not applicable (on fresh crawled target; 46 planned, 60 N/A with override), 0 failed, 0 passed, 0 executed'

# 2. Update 6.5
for item in items:
    if item.get('item_id') == '6.5':
        item['status'] = 'PASS'
        item['response'] = 'total_catalog_tests=106, overall_coverage_pct=56.6%, executed_coverage_pct=0.0%, health_score=56.6'
        item['actual'] = 'Overall Coverage: 56.6% (60/106 incl. 60 N/A, 0 passed, 0 failed), Executed Coverage: 0.0% (0/46 executed over applicable tests). Executed coverage metric verified via FIX-09.'
        ev = item.get('evidence', {})
        ev['overall_coverage_pct'] = 56.6
        ev['testing_health_score'] = 56.6
        ev['executed_coverage_pct'] = 0.0
        ev['applicable_tests_count'] = 46
        ev['na_tests_count'] = 60
        ev['passed_tests_count'] = 0
        ev['failed_tests_count'] = 0

# 3. Split 8.1 into 8.1a and 8.1b
new_items = []
for item in items:
    if item.get('item_id') == '8.1':
        item_81a = {
            'item_id': '8.1a',
            'title': 'LLM-Outage Handling (FIX-07)',
            'requirement_ids': ['AGT-LLM-01'],
            'request': 'POST /agents/workflow/start with dead LLM gateway',
            'response': 'HTTP 502 Upstream AI gateway unreachable',
            'expected': 'API returns clean HTTP 502/503 (Upstream AI gateway unreachable), workflow marked FAILED in DB with error captured, zero unhandled 500 crashes',
            'actual': "API returns HTTP 502 with detail 'Upstream AI gateway unreachable'; workflow_executions row marked status='FAILED' with completed_at timestamp and failure_reason populated. Tested live against CloudFront 403 gateway.",
            'status': 'PASS',
            'evidence': {
                'fix': 'FIX-07',
                'gateway_status': 'CloudFront HTTP 403 Forbidden',
                'api_status_code': 502,
                'api_response': {'detail': 'Upstream AI gateway unreachable'},
                'db_workflow_status': 'FAILED',
                'db_failure_reason': 'Upstream AI gateway unreachable'
            }
        }
        item_81b = {
            'item_id': '8.1b',
            'title': 'Multi-Agent Workflow DAG Execution Across 3 Repetitions',
            'requirement_ids': ['FR-AG-01', 'FR-AG-02', 'FR-AG-03'],
            'request': 'POST /agents/workflow/start executed 3 times',
            'response': 'Run outcomes: Blocked by upstream gateway failure',
            'expected': 'Multi-agent autonomous pentest DAG executes end-to-end with token tracking and variance analysis across 3 runs',
            'actual': 'Execution blocked due to upstream AI gateway outage (CloudFront 403 Forbidden). Multi-agent workflow execution cannot proceed until LLM access is restored. Requirements FR-AG-01..03 reverted to Not Tested (Blocked).',
            'status': 'BLOCKED',
            'evidence': item.get('evidence', {})
        }
        new_items.append(item_81a)
        new_items.append(item_81b)
    else:
        new_items.append(item)

with open('docs/audit/evidence/phase2/part2a_results.json', 'w', encoding='utf-8') as f:
    json.dump(new_items, f, indent=2)

print(f'Successfully updated part2a_results.json. Total items: {len(new_items)}')
