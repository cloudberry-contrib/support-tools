# Apache Cloudberry (Incubating) Support Scripts

This directory contains support scripts for Apache Cloudberry (Incubating) administration and troubleshooting.

## Core File Analyzer

`apache_cloudberry_core_analyzer.py` is a utility for analyzing PostgreSQL core files in Apache Cloudberry (Incubating) environments.

### Installation

```bash
chmod +x apache_cloudberry_core_analyzer.py
```

### Usage Examples

1. Analyze a single core file:
```bash
./apache_cloudberry_core_analyzer.py /var/core/core.1234
```

2. Analyze a core file and store results in a specific directory:
```bash
./apache_cloudberry_core_analyzer.py --output-dir ~/core_analysis /var/core/core.1234
```

3. Analyze all core files in a directory:
```bash
./apache_cloudberry_core_analyzer.py /var/core/
```

4. Analyze using a specific core file pattern:
```bash
./apache_cloudberry_core_analyzer.py --core-pattern="core-*" /var/core/
```

5. Analyze the most recent 5 core files:
```bash
./apache_cloudberry_core_analyzer.py --max-cores 5 /var/core/
```

6. Analyze and compare multiple core files:
```bash
./apache_cloudberry_core_analyzer.py --compare /var/core/
```

### Output Files

The script generates JSON format output files:

1. Individual Analysis Files:
```bash
core_analysis_YYYYMMDD_HHMMSS.json
```

2. Comparison Results (when using --compare):
```bash
core_comparison_YYYYMMDD_HHMMSS.json
```

### Viewing Output

To view the JSON output in a readable format:

```bash
# Using Python's json tool
python3 -m json.tool core_analysis_YYYYMMDD_HHMMSS.json

# Using less
less core_analysis_YYYYMMDD_HHMMSS.json

# Using jq (if installed)
jq '.' core_analysis_YYYYMMDD_HHMMSS.json
```

### Requirements

- Python 3.6 or later
- GDB (GNU Debugger)
- Apache Cloudberry (Incubating) environment (GPHOME must be set)
- Sufficient permissions to read core files
- Rocky Linux 8 compatible

### Command Line Options

```
usage: apache_cloudberry_core_analyzer.py [-h] [--output-dir OUTPUT_DIR]
                                        [--max-cores MAX_CORES] [--compare]
                                        [--core-pattern PATTERN]
                                        core_path

positional arguments:
  core_path             Path to core file or directory containing core files

optional arguments:
  -h, --help           show this help message and exit
  --output-dir DIR     Directory to store analysis results
  --max-cores N        Maximum number of core files to analyze
  --compare            Compare core files and identify patterns
  --core-pattern PAT   Custom core file pattern (e.g., 'core-*' or 'core.*')
```
