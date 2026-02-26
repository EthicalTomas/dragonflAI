```
backend/
  app/
    api/
      routes/
        findings.py       # CRUD + report generation + export endpoints
        health.py
        programs.py
        runs.py
        targets.py
    core/
      config.py
      logging.py
    db/
      base.py
      session.py
    llm/
      base.py
      null_provider.py
    models/
      finding.py          # Finding model + Severity + FindingStatus
      program.py
      run.py
      target.py
    parsers/
      burp_parser.py
      httpx_parser.py
      nmap_parser.py
      subfinder_parser.py
      zap_parser.py
    reports/
      __init__.py
      cvss.py             # CVSS 3.1 calculator
      generator.py        # ReportGenerator class
      templates.py        # Markdown report templates (full, summary, platform)
    runs/
      orchestrator.py
    schemas/
      finding.py          # FindingCreate, FindingUpdate, FindingOut, FindingSummary
      program.py
      run.py
      target.py
    scope/
      parser.py
      validator.py
    services/
      runs_service.py
    tools/
      base.py
      dnsx.py
      httpx_probe.py
      nmap.py
      subfinder.py
    main.py
docs/
  roadmap.md
  safety.md
  setup.md
infra/
  docker-compose.yml
migrations/
  env.py
  versions/
scripts/
  dev.sh
ui/
  pages/
    1_Programs.py
    2_Targets.py
    3_Runs.py
    4_Assets.py
    5_Endpoints.py
    6_Diffs.py
    7_Findings.py         # Create/list/manage findings + generate reports
    8_Reports.py          # View/export/batch reports dashboard
  api_client.py
  app.py
worker/
  jobs/
    execute_run.py
  worker.py
```
