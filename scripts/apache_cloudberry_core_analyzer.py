#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Apache CloudBerry (Incubating) Core Analyzer
A tool for analyzing PostgreSQL core files in production environments
"""

import os
import subprocess
import json
import datetime
import re
from pathlib import Path
from typing import List, Dict, Optional

class PostgresCoreAnalyzer:
    def __init__(self, data_dir: str = "/var/log/postgres_cores", core_pattern: str = None):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.core_pattern = core_pattern
        self.analyzed_cores = []  # Store analysis results for comparison

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _find_core_files(self, path: str) -> List[str]:
        """Find core files in directory or return single file."""
        path = Path(path)
        if path.is_file():
            return [str(path)]

        # Look for files matching core pattern
        core_files = set()  # Use a set to avoid duplicates

        # Use custom pattern if provided, otherwise use defaults
        if self.core_pattern:
            patterns = [self.core_pattern]
            print(f"Using custom pattern: {self.core_pattern}")
        else:
            patterns = [
                "core.*",                # Standard core pattern
                "*.core",                # Alternative pattern
                "core",                  # Simple core file
                "core-*",                # systemd pattern
                "**/core-*-*-*-*-*",    # Full systemd pattern with PID
            ]
            print("Using default patterns:")
            for pattern in patterns:
                print(f"  - {pattern}")

        # Try each pattern
        total_found = 0
        for pattern in patterns:
            try:
                found = list(path.glob(pattern))
                if found:
                    total_found += len(found)
                    print(f"Found {len(found)} file(s) matching pattern: {pattern}")
                    for f in found:
                        core_files.add(str(f))
            except Exception as e:
                print(f"Error with pattern {pattern}: {e}")

        # Convert to list and sort by modification time
        core_files = sorted(
            core_files,
            key=lambda x: os.path.getmtime(x),
            reverse=True
        )

        if total_found != len(core_files):
            print(f"\nNote: Found {total_found} total matches, {len(core_files)} unique files")
        else:
            print(f"\nTotal core files found: {len(core_files)}")

        return core_files

    def find_postgres_binary(self) -> Optional[str]:
        """Find Apache CloudBerry (Incubating) postgres binary using GPHOME environment variable."""
        gphome = os.getenv('GPHOME')
        if not gphome:
            print("ERROR: GPHOME environment variable must be set")
            return None

        postgres_path = os.path.join(gphome, 'bin', 'postgres')
        if not os.path.exists(postgres_path):
            print(f"ERROR: PostgreSQL binary not found at {postgres_path}")
            return None

        print(f"Using PostgreSQL binary: {postgres_path}")
        try:
            os.access(postgres_path, os.X_OK)
            print("Binary is executable")
        except Exception as e:
            print(f"WARNING: Could not check binary permissions: {e}")

        return postgres_path

    def analyze_cores(self, core_path: str, max_cores: int = None) -> List[Dict]:
        """Analyze multiple core files from a directory or a single file."""
        core_files = self._find_core_files(core_path)

        if max_cores:
            if len(core_files) > max_cores:
                print(f"\nLimiting analysis to {max_cores} most recent core files")
                core_files = core_files[:max_cores]

        if not core_files:
            print("\nNo core files found to analyze")
            return []

        results = []
        for i, core_file in enumerate(core_files, 1):
            print(f"\nAnalyzing core file {i}/{len(core_files)}: {core_file}")
            try:
                analysis = self.analyze_core_file(core_file)
                results.append(analysis)
                self.analyzed_cores.append(analysis)

                # Save individual analysis
                output_file = self.save_analysis(analysis)
                print(f"✓ Analysis saved to: {output_file}")

            except Exception as e:
                print(f"Error analyzing {core_file}: {e}")

        return results

    def analyze_core_file(self, core_file: str) -> Dict:
        """Analyze a PostgreSQL core file and return findings."""
        if not os.path.exists(core_file):
            raise FileNotFoundError(f"Core file not found: {core_file}")

        print("\nStarting core file analysis...")
        print(f"Core file: {core_file}")

        try:
            core_stat = os.stat(core_file)
            print(f"Core file size: {core_stat.st_size:,} bytes")
            print(f"Core file permissions: {oct(core_stat.st_mode)[-3:]}")
        except Exception as e:
            print(f"WARNING: Could not get core file stats: {e}")

        analysis = {
            "timestamp": datetime.datetime.now().isoformat(),
            "core_file": core_file,
            "file_info": self._get_file_info(core_file),
            "basic_info": {},
            "stack_trace": [],
            "threads": [],
            "registers": {},
            "signal_info": {},
            "shared_libraries": [],
            "postgres_info": {}
        }

        # Find PostgreSQL binary
        print("\nLooking for Apache CloudBerry (Incubating) PostgreSQL binary...")
        postgres_binary = self.find_postgres_binary()
        if not postgres_binary:
            print("ERROR: Could not find PostgreSQL binary, analysis will be limited")
            return analysis

        print(f"Found PostgreSQL binary: {postgres_binary}")
        analysis["postgres_info"]["binary_path"] = postgres_binary

        # Verify we can use GDB on the binary
        print("\nVerifying GDB access to binary...")
        try:
            cmd = ["gdb", "-nx", "--batch", "-ex", "quit", postgres_binary]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            if result.returncode != 0:
                print(f"WARNING: GDB test on binary failed: {result.stderr}")
        except Exception as e:
            print(f"ERROR: Could not test GDB on binary: {e}")

        # Run GDB analysis
        analysis.update(self._get_gdb_analysis(postgres_binary, core_file))

        return analysis

    def _get_file_info(self, core_file: str) -> Dict:
        """Get basic file information about the core file."""
        result = subprocess.run(
            ["file", core_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        return {
            "file_output": result.stdout.strip(),
            "size": os.path.getsize(core_file),
            "created": datetime.datetime.fromtimestamp(
                os.path.getctime(core_file)
            ).isoformat()
        }

    def _get_gdb_analysis(self, binary: str, core_file: str) -> Dict:
        """Run GDB analysis on the core file."""
        print("\nRunning GDB analysis...")

        analysis = {
            "stack_trace": [],
            "threads": [],
            "registers": {},
            "signal_info": {},
            "shared_libraries": []
        }

        gdb_commands = [
            "set pagination off",
            "set print pretty on",
            "set print object on",
            "info threads",
            "thread apply all bt full",
            "info registers all",
            "info signal SIGABRT",  # Check specific signals
            "info signal SIGSEGV",
            "info signal SIGBUS",
            "print $_siginfo",      # Get detailed signal info
            "info sharedlibrary",
            "x/1i $pc",
            "quit"
        ]

        try:
            cmd = ["gdb", "-nx", "--batch"]
            for gdb_cmd in gdb_commands:
                cmd.extend(["-ex", gdb_cmd])
            cmd.extend([binary, core_file])

            print("Executing GDB commands...")
            print(f"Command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            if result.returncode != 0:
                print(f"WARNING: GDB returned non-zero exit code: {result.returncode}")
                print("GDB stderr output:")
                print(result.stderr)

            # Parse GDB output
            output = result.stdout
            if not output.strip():
                print("WARNING: No output received from GDB")
            else:
                print(f"Received {len(output)} bytes of GDB output")

                # Parse all components
                analysis["stack_trace"] = self._parse_backtrace(output)
                analysis["threads"] = self._parse_threads(output)
                analysis["registers"] = self._parse_registers(output)
                analysis["signal_info"] = self._parse_signal_info(output)
                analysis["shared_libraries"] = self._parse_shared_libraries(output)

                # Print summary
                print(f"\nAnalysis Summary:")
                print(f"  Stack frames: {len(analysis['stack_trace'])}")
                print(f"  Threads: {len(analysis['threads'])}")
                print(f"  Registers: {len(analysis['registers'])}")
                if analysis['signal_info']:
                    print(f"  Signal: {analysis['signal_info'].get('signal_name', 'Unknown')}")
                    print(f"  Description: {analysis['signal_info'].get('signal_description', 'Unknown')}")
                if analysis['shared_libraries']:
                    print(f"  Shared libraries: {len(analysis['shared_libraries'])}")

        except Exception as e:
            print(f"ERROR: GDB analysis failed: {e}")

        return analysis

    def _parse_backtrace(self, gdb_output: str) -> List[Dict]:
        """Parse GDB backtrace output."""
        bt_lines = []
        for line in gdb_output.splitlines():
            if line.startswith("#"):
                frame = {}
                match = re.match(r"#(\d+)\s+([^in]+)in\s+(\S+)\s*\(([^)]*)\)", line)
                if match:
                    frame["frame_num"] = match.group(1)
                    frame["location"] = match.group(2).strip()
                    frame["function"] = match.group(3)
                    frame["args"] = match.group(4)
                    bt_lines.append(frame)
        return bt_lines

    def _parse_threads(self, gdb_output: str) -> List[Dict]:
        """Parse GDB thread information."""
        threads = []
        current_thread = None

        for line in gdb_output.splitlines():
            # Start of a new thread section
            thread_match = re.match(r"Thread\s+(\d+)\s+\(.*?(?:LWP\s+(\d+)|Thread[^)]+)\)", line)
            if thread_match:
                current_thread = {
                    "thread_id": thread_match.group(1),
                    "lwp_id": thread_match.group(2) if thread_match.group(2) else "unknown",
                    "backtrace": []
                }
                threads.append(current_thread)
            # Backtrace line within a thread
            elif current_thread and line.startswith("#"):
                frame_match = re.match(r"#(\d+)\s+([^in]+)in\s+(\S+)\s*\(([^)]*)\)", line)
                if frame_match:
                    current_thread["backtrace"].append({
                        "frame_num": frame_match.group(1),
                        "location": frame_match.group(2).strip(),
                        "function": frame_match.group(3),
                        "args": frame_match.group(4)
                    })

        return threads

    def _parse_registers(self, gdb_output: str) -> Dict:
        """Parse GDB register information."""
        registers = {}
        for line in gdb_output.splitlines():
            # Match register lines (rax, eax, r8, etc.)
            if re.match(r"^[re][a-z][a-z]|^r\d+|^[cdefgs]s|^[re]ip|^[re]flags", line):
                parts = line.split()
                if len(parts) >= 2:
                    reg_name = parts[0]
                    reg_value = parts[1]
                    registers[reg_name] = {
                        "value": reg_value,
                        "hex": hex(int(reg_value, 16)) if reg_value.startswith("0x") else reg_value
                    }
        return registers

    def _parse_signal_info(self, gdb_output: str) -> Dict:
        """Parse signal information from GDB output."""
        signal_info = {}

        # Try to get signal from $_siginfo
        for line in gdb_output.splitlines():
            if "$_siginfo =" in line:
                # Extract signal number and code
                signal_match = re.search(r"si_signo = (\d+).*?si_code = (\d+)", line)
                if signal_match:
                    signo = int(signal_match.group(1))
                    code = int(signal_match.group(2))
                    signal_info = {
                        "signal_number": signo,
                        "signal_code": code,
                        "signal_name": self._get_signal_name(signo),
                        "signal_description": self._get_signal_description(signo, code)
                    }
                # For SIGSEGV, try to get fault address
                fault_addr_match = re.search(r"si_addr = (0x[0-9a-fA-F]+)", line)
                if fault_addr_match:
                    signal_info["fault_address"] = fault_addr_match.group(1)

            # Also check signal info output
            elif "Signal " in line and "Stop" in line:
                signal_match = re.match(r"Signal\s+(\d+)\s+\(([A-Z]+)\)", line)
                if signal_match and "signal_name" not in signal_info:
                    signo = int(signal_match.group(1))
                    name = signal_match.group(2)
                    signal_info = {
                        "signal_number": signo,
                        "signal_name": name,
                        "signal_description": self._get_signal_description(signo, 0)
                    }

        # Check backtrace for abort/assertion failures
        if not signal_info:
            for line in gdb_output.splitlines():
                if "abort" in line.lower() or "assertion" in line.lower():
                    signal_info = {
                        "signal_number": 6,
                        "signal_name": "SIGABRT",
                        "signal_description": "Abort due to assertion failure or abort() call"
                    }
                    break

        return signal_info

    def _get_signal_name(self, signo: int) -> str:
        """Convert signal number to name."""
        signal_names = {
            1: "SIGHUP",
            2: "SIGINT",
            3: "SIGQUIT",
            4: "SIGILL",
            6: "SIGABRT",
            8: "SIGFPE",
            9: "SIGKILL",
            11: "SIGSEGV",
            13: "SIGPIPE",
            14: "SIGALRM",
            15: "SIGTERM"
        }
        return signal_names.get(signo, f"SIGNAL_{signo}")

    def _get_signal_description(self, signo: int, code: int) -> str:
        """Get human-readable description of signal."""
        if signo == 11:  # SIGSEGV
            codes = {
                1: "SEGV_MAPERR (Address not mapped to object)",
                2: "SEGV_ACCERR (Invalid permissions for mapped object)",
                3: "SEGV_BNDERR (Failed address bound checks)",
                4: "SEGV_PKUERR (Access was denied by memory protection keys)"
            }
            return codes.get(code, f"SIGSEGV with code {code}")

        elif signo == 6:  # SIGABRT
            return "Process abort signal (possibly assertion failure)"

        elif signo == 7:  # SIGBUS
            codes = {
                1: "BUS_ADRALN (Invalid address alignment)",
                2: "BUS_ADRERR (Nonexistent physical address)",
                3: "BUS_OBJERR (Object-specific hardware error)"
            }
            return codes.get(code, f"SIGBUS with code {code}")

        elif signo == 8:  # SIGFPE
            codes = {
                1: "FPE_INTDIV (Integer divide by zero)",
                2: "FPE_INTOVF (Integer overflow)",
                3: "FPE_FLTDIV (Floating point divide by zero)",
                4: "FPE_FLTOVF (Floating point overflow)",
                5: "FPE_FLTUND (Floating point underflow)",
                6: "FPE_FLTRES (Floating point inexact result)",
                7: "FPE_FLTINV (Invalid floating point operation)",
                8: "FPE_FLTSUB (Subscript out of range)"
            }
            return codes.get(code, f"SIGFPE with code {code}")

        return f"Signal {signo} with code {code}"

    def _parse_shared_libraries(self, gdb_output: str) -> List[Dict]:
        """Parse shared library information."""
        libraries = []
        for line in gdb_output.splitlines():
            if "0x" in line and line.endswith(".so"):
                parts = line.split()
                if len(parts) >= 4:
                    libraries.append({
                        "name": parts[-1],
                        "start_addr": parts[0],
                        "end_addr": parts[1]
                    })
        return libraries

    def compare_cores(self, analyses: List[Dict] = None) -> Dict:
        """Compare core files to identify similarities."""
        if analyses is None:
            analyses = self.analyzed_cores

        if len(analyses) < 2:
            return {"message": "Need at least 2 core files to compare"}

        comparison = {
            "total_cores": len(analyses),
            "common_signals": self._find_common_signals(analyses),
            "common_functions": self._find_common_functions(analyses),
            "crash_patterns": self._identify_crash_patterns(analyses)
        }

        return comparison

    def _find_common_signals(self, analyses: List[Dict]) -> Dict:
        """Find common signals across core files."""
        signals = {}
        for analysis in analyses:
            signal_info = analysis.get("signal_info", {})
            signal_name = signal_info.get("signal_name", "Unknown")
            signals[signal_name] = signals.get(signal_name, 0) + 1

        return {
            "signal_distribution": signals,
            "most_common": max(signals.items(), key=lambda x: x[1]) if signals else None
        }

    def _find_common_functions(self, analyses: List[Dict]) -> Dict:
        """Find common functions in stack traces."""
        function_counts = {}
        crash_functions = {}  # Functions at top of stack

        for analysis in analyses:
            if "stack_trace" in analysis and analysis["stack_trace"]:
                # Count all functions in stack
                for frame in analysis["stack_trace"]:
                    func = frame.get("function", "Unknown")
                    function_counts[func] = function_counts.get(func, 0) + 1

                # Record crash function (top of stack)
                crash_func = analysis["stack_trace"][0].get("function", "Unknown")
                crash_functions[crash_func] = crash_functions.get(crash_func, 0) + 1

        return {
            "most_common_functions": sorted(
                function_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5],
            "crash_function_distribution": crash_functions
        }

    def _identify_crash_patterns(self, analyses: List[Dict]) -> List[Dict]:
        """Identify common crash patterns."""
        patterns = []

        # Group by signal and top N stack frames
        crash_groups = {}
        for analysis in analyses:
            signal = analysis.get("signal_info", {}).get("signal_name", "Unknown")
            stack_signature = []

            # Get top 3 frames as signature
            for frame in analysis.get("stack_trace", [])[:3]:
                func = frame.get("function", "Unknown")
                stack_signature.append(func)

            signature = (signal, tuple(stack_signature))
            if signature not in crash_groups:
                crash_groups[signature] = []
            crash_groups[signature].append(analysis["core_file"])

        # Convert groups to patterns
        for (signal, stack), core_files in crash_groups.items():
            if len(core_files) > 1:  # Only include if pattern appears multiple times
                patterns.append({
                    "signal": signal,
                    "stack_signature": list(stack),
                    "occurrence_count": len(core_files),
                    "core_files": core_files
                })

        return sorted(patterns, key=lambda x: x["occurrence_count"], reverse=True)

    def save_analysis(self, analysis: Dict):
        """Save analysis results to a file."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.data_dir / f"core_analysis_{timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(analysis, f, indent=2)

        return filename

def check_required_tools() -> bool:
    """Check if required external tools are available."""
    print("Checking required tools...")
    required_tools = ['gdb']
    missing_tools = []

    # Check GPHOME environment variable
    gphome = os.getenv('GPHOME')
    if not gphome:
        print("ERROR: GPHOME environment variable is not set")
        return False
    print(f"Found GPHOME: {gphome}")

    for tool in required_tools:
        try:
            result = subprocess.run(
                ['which', tool],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True  # This makes stdout/stderr return strings instead of bytes
            )
            if result.returncode != 0:
                missing_tools.append(tool)
        except Exception as e:
            print(f"Error checking for {tool}: {e}")
            missing_tools.append(tool)

    if missing_tools:
        logging.error(f"Required tools missing: {', '.join(missing_tools)}")
        logging.error("Please install the missing tools and try again")
        return False
    return True

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Apache CloudBerry (Incubating) Core Analyzer")
    parser.add_argument("core_path", help="Path to core file or directory containing core files")
    parser.add_argument("--output-dir", default="/var/log/postgres_cores",
                      help="Directory to store analysis results")
    parser.add_argument("--max-cores", type=int,
                      help="Maximum number of core files to analyze")
    parser.add_argument("--core-pattern",
                      help="Custom core file pattern (e.g., 'core-*' or 'core.*')")
    parser.add_argument("--compare", action="store_true",
                      help="Compare core files and identify patterns")

    args = parser.parse_args()

    print("\nApache CloudBerry (Incubating) Core Analyzer")
    print("=" * 30)

    if not check_required_tools():
        exit(1)

    analyzer = PostgresCoreAnalyzer(
        data_dir=args.output_dir,
        core_pattern=args.core_pattern
    )

    try:
        print("\nStarting analysis...")

        # Analyze core files
        analyses = analyzer.analyze_cores(args.core_path, args.max_cores)

        if not analyses:
            print("No core files were analyzed successfully")
            exit(1)

        # Compare if requested and multiple cores were analyzed
        if args.compare and len(analyses) > 1:
            print("\nComparing core files...")
            comparison = analyzer.compare_cores(analyses)

            print("\nCore File Comparison Results:")
            print("-" * 30)

            if "common_signals" in comparison:
                print("\nSignal Distribution:")
                print("------------------")
                for signal, count in comparison["common_signals"]["signal_distribution"].items():
                    print(f"  {signal:15} : {count:3d} occurrences")
                most_common = comparison["common_signals"].get("most_common")
                if most_common:
                    print(f"\n  Most common signal: {most_common[0]} ({most_common[1]} occurrences)")

            if "common_functions" in comparison:
                print("\nMost Common Functions in Stack Traces:")
                print("----------------------------------")
                for func, count in comparison["common_functions"]["most_common_functions"]:
                    print(f"  {func:40} : {count:3d} occurrences")

            if "crash_patterns" in comparison:
                print("\nCrash Patterns:")
                print("--------------")
                for i, pattern in enumerate(comparison["crash_patterns"], 1):
                    print(f"\nPattern {i} (occurred {pattern['occurrence_count']} times):")
                    print(f"  Signal: {pattern['signal']}")
                    print(f"  Stack Signature:")
                    for j, func in enumerate(pattern['stack_signature'], 1):
                        print(f"    {j}. {func}")
                    print(f"  Affected core files:")
                    for core_file in pattern['core_files']:
                        print(f"    - {os.path.basename(core_file)}")
                print(f"\nTotal unique crash patterns: {len(comparison['crash_patterns'])}")

            # Save comparison results
            comparison_file = analyzer.data_dir / f"core_comparison_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(comparison_file, 'w') as f:
                json.dump(comparison, f, indent=2)
            print(f"\n✓ Comparison results saved to: {comparison_file}")

        print("\n✓ Analysis complete")

    except Exception as e:
        logging.error(f"Analysis failed: {e}")
        exit(1)

if __name__ == "__main__":
    main()
