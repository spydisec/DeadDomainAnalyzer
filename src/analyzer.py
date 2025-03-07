#!/usr/bin/env python3
import asyncio
import random
import logging
import yaml
import csv
import json
import sys
import time
from pathlib import Path
from datetime import datetime
from logging.handlers import RotatingFileHandler
from collections import defaultdict
from tqdm import tqdm
import backoff  # Install with: pip install backoff

CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"

class StatisticsTracker:
    def __init__(self, config: dict):
        self.config = config["statistics"]
        self.stats_dir = Path(self.config["directory"])
        self.stats_dir.mkdir(parents=True, exist_ok=True)
        
        self.stats = defaultdict(lambda: {
            "total": 0, "success": 0, "error": 0,
            "timeout": 0, "servfail": 0
        })
        
        self.working_file = self.stats_dir / self.config["working_file"]
        self._load_working_file()

    def _load_working_file(self):
        if self.working_file.exists():
            try:
                with open(self.working_file) as f:
                    loaded_stats = json.load(f)
                    for resolver, stats in loaded_stats.items():
                        self.stats[resolver].update(stats)
            except json.JSONDecodeError:
                logging.warning("Corrupted statistics file, starting fresh")

    def record_query(self, resolver: str, status: str):
        self.stats[resolver]["total"] += 1
        self.stats[resolver][status] += 1
        total_queries = sum(stats["total"] for stats in self.stats.values())
        if total_queries % 100 == 0:
            self._save_working_file()

    def _save_working_file(self):
        with open(self.working_file, "w") as f:
            json.dump(self.stats, f)

    def generate_report(self):
        report_path = self.stats_dir / self.config["output_file"]
        report_time = datetime.now().isoformat()
        
        headers = ["timestamp", "resolver", "total", "success_rate",
                  "error_rate", "timeout_rate", "servfail_rate"]
        
        if not report_path.exists():
            with open(report_path, "w", newline="") as f:
                csv.writer(f).writerow(headers)
        
        with open(report_path, "a", newline="") as f:
            writer = csv.writer(f)
            for resolver, stats in self.stats.items():
                total = stats["total"]
                writer.writerow([
                    report_time,
                    resolver,
                    total,
                    stats["success"] / total if total else 0,
                    stats["error"] / total if total else 0,
                    stats["timeout"] / total if total else 0,
                    stats["servfail"] / total if total else 0
                ])

class DomainAnalyzer:
    def __init__(self):
        self.config = self._load_config()
        self.logger = self._setup_logging()
        self.stats_tracker = StatisticsTracker(self.config)
        self._validate_config()

    def _load_config(self) -> dict:
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f)

    def _setup_logging(self):
        log_cfg = self.config["logging"]
        logger = logging.getLogger("DomainAnalyzer")
        logger.setLevel(log_cfg["level"])
        
        # Remove any existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Disable logging if turned off in the config
        if not log_cfg.get("enabled", True):
            logger.disabled = True
            return logger
        
        log_dir = Path(log_cfg["directory"])
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_dir / "analysis.log",
            maxBytes=self._parse_size(log_cfg["max_size"]),
            backupCount=log_cfg["backups"]
        )
        
        file_handler.setFormatter(self._get_formatter())
        logger.addHandler(file_handler)
        return logger

    def _get_formatter(self):
        return logging.Formatter(
            "%(asctime)s - %(levelname)s - %(name)s - %(message)s"
        )

    def _parse_size(self, size_str: str) -> int:
        units = {"B": 1, "KB": 10**3, "MB": 10**6, "GB": 10**9}
        num = size_str[:-2]
        unit = size_str[-2:].upper()
        return int(num) * units.get(unit, 1)

    def _validate_config(self):
        required = ["inputs", "outputs", "resolvers", "statistics", "logging"]
        for section in required:
            if section not in self.config:
                raise ValueError(f"Missing config section: {section}")

    @backoff.on_exception(backoff.expo, (asyncio.TimeoutError, Exception), max_tries=5)
    async def _execute_dig(self, domain, resolver):
        self.logger.debug(f"Querying {domain} via {resolver}")
        cmd = [
            "dig", "+short",
            "+https" if "doh" in resolver else "",
            "+tls" if "doh" in resolver else "",
            f"@{resolver}", "+time=5", domain
        ]
        status = "error"
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config["timeout"]
            )
        except asyncio.TimeoutError:
            status = "timeout"
        except Exception as e:
            self.logger.error(f"Subprocess error: {str(e)}")
        else:
            output = stdout.decode().strip()
            error = stderr.decode().strip()
            if proc.returncode != 0:
                status = "error"
            elif "SERVFAIL" in error:
                status = "servfail"
            elif not output:
                status = "dead"
            else:
                status = "success"
        finally:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
        
        self.stats_tracker.record_query(resolver, status)
        return status, resolver

    async def _check_domain(self, domain: str) -> str:
        resolvers = self.config["resolvers"]["doh"].copy() + self.config["resolvers"].get("dns", [])
        for attempt in range(1, self.config["max_attempts"] + 1):
            if not resolvers:
                break
            resolver = random.choice(resolvers)
            status, _ = await self._execute_dig(domain, resolver)
            if status in ["success", "dead"]:
                return status
            resolvers.remove(resolver)
        return "error"

    async def _process_batch(self, domains, writers):
        tasks = [self._process_single(domain.strip(), writers) for domain in domains if domain.strip()]
        await asyncio.gather(*tasks)

    async def _process_single(self, domain: str, writers: dict):
        try:
            status = await self._check_domain(domain)
            # Update progress bar after each domain is processed
            self.progress_bar.update(1)
            if status in writers:
                writers[status].write(f"{domain}\n")
        except Exception as e:
            self.logger.error(f"Failed {domain}: {str(e)}")

    def _count_domains(self) -> int:
        total = 0
        for input_cfg in self.config["inputs"]:
            path = Path(input_cfg["path"])
            if path.exists():
                with open(path) as f:
                    total += len([line for line in f if line.strip()])
        return total

    async def analyze(self):
        self.logger.info("Starting domain analysis")
        output_dir = Path(self.config["outputs"]["directory"])
        output_dir.mkdir(parents=True, exist_ok=True)
        
        total_domains = self._count_domains()
        if self.config.get("dry_run", False):
            total_domains = min(total_domains, 100)
            self.logger.warning(f"DRY RUN: Limiting to {total_domains} domains")
        
        # Prepare writers for output
        writers = {}
        for status in ["dead", "error", "alive", "servfail"]:
            if self.config["outputs"]["enabled"].get(status, False):
                path = output_dir / self.config["outputs"]["filenames"][status]
                writers[status] = open(path, "a")
        
        # Initialize progress bar
        progress_conf = self.config.get("progress", {})
        mininterval = progress_conf.get("mininterval", 0.5)  # default to 0.5 sec
        self.progress_bar = tqdm(total=total_domains, desc="Processing domains",
                                unit="domain", ncols=80, mininterval=mininterval)
        
        try:
            for input_cfg in self.config["inputs"]:
                path = Path(input_cfg["path"])
                if not path.exists():
                    self.logger.error(f"Missing input: {path}")
                    continue
                
                with open(path) as f:
                    domains = [line.strip() for line in f if line.strip()]
                    if self.config.get("dry_run", False):
                        domains = domains[:100]
                
                batch_size = self.config.get("concurrency", 50)
                for i in range(0, len(domains), batch_size):
                    batch = domains[i:i + batch_size]
                    await self._process_batch(batch, writers)
        finally:
            for writer in writers.values():
                writer.close()
            self.progress_bar.close()
            self.stats_tracker.generate_report()
            self.stats_tracker._save_working_file()
            self.logger.info("Analysis completed successfully")

if __name__ == "__main__":
    try:
        analyzer = DomainAnalyzer()
        asyncio.run(analyzer.analyze())
    except KeyboardInterrupt:
        logging.info("Analysis interrupted by user")
    except Exception as e:
        logging.critical(f"Critical failure: {str(e)}")
        raise
