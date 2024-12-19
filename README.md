# Apache Cloudberry (Incubating) Support Tools

This repository contains a collection of tools to assist in supporting Apache Cloudberry (Incubating) deployments.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

## Tools

### Core File Analyzer

Location: `scripts/apache_cloudberry_core_analyzer.py`

A utility for analyzing PostgreSQL core files in Apache Cloudberry (Incubating) environments. It provides detailed analysis of core dumps and can identify patterns across multiple core files.

#### Features

- Single core file analysis with detailed GDB inspection
- Multiple core file analysis with pattern detection
- Signal and stack trace analysis
- Shared library dependency inspection
- JSON output for further processing
- Comparison of multiple core files to identify common crash patterns
- Custom core file pattern matching
- Pretty-printed JSON output for readability

#### Requirements

- Python 3.6+
- GDB (GNU Debugger)
- Apache Cloudberry (Incubating) environment (GPHOME must be set)
- Rocky Linux 8 compatible

#### Basic Usage

1. Analyze a single core file:
```bash
./apache_cloudberry_core_analyzer.py /path/to/core.1234
```

2. Analyze all core files in a directory:
```bash
./apache_cloudberry_core_analyzer.py /path/to/core/files/
```

3. Analyze and compare multiple core files:
```bash
./apache_cloudberry_core_analyzer.py /path/to/core/files/ --compare
```

4. Custom core pattern matching:
```bash
./apache_cloudberry_core_analyzer.py --core-pattern="core-*" /path/to/core/files/
```

5. View the JSON output:
```bash
# Using Python's json.tool
cat core_analysis_YYYYMMDD_HHMMSS.json | python3 -m json.tool

# Using less
less core_analysis_YYYYMMDD_HHMMSS.json
```

#### Output Format

The analyzer produces JSON output files for both individual analyses and comparisons:
- Individual analysis: `core_analysis_YYYYMMDD_HHMMSS.json`
- Comparison results: `core_comparison_YYYYMMDD_HHMMSS.json`

The JSON format is chosen for:
- Structured representation of analysis data
- Easy programmatic processing
- Human readability with proper formatting
- Tool integration capabilities

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Getting Help

For questions and support:
1. Check the documentation in the `scripts/` directory
2. File an issue in the GitHub repository
3. Provide relevant sections of core analysis when reporting issues

## Acknowledgments

This project builds on the excellent work of the PostgreSQL and GDB communities.
