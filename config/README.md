# Path Configuration

Machine-specific paths are stored in `config/paths.json`. Relative paths in that file are resolved from `base_dir`.

Example:

```json
{
  "base_dir": "..",
  "input_config": "input/test_case_sample.json",
  "output_dir": "data/target_commandline_tests",
  "rules_dir": "rules",
  "zircolite": {
    "path": "%ZIRCOLITE_HOME%/zircolite.py",
    "python_exe": null,
    "ruleset": "%ZIRCOLITE_HOME%/rules_sysmon.json",
    "config": null
  }
}
```

Run with the config file:

```powershell
$env:PYTHONPATH='src'
python -m sigma_rule_evaluator.cli --limit 1
```

CLI path arguments such as `--config`, `--output-dir`, `--zircolite-path`, `--ruleset`, and `--rules-dir` override values from `config/paths.json`.
