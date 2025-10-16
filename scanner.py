import socket, time, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Callable, Any

logging.basicConfig(filename='scan_errors.log', level=logging.INFO)

class PortScanner:
    def __init__(self, timeout_ms=800, max_workers=200):
        self.timeout = timeout_ms/1000.0
        self.max_workers = max_workers
        self._stop = False

    def stop(self): self._stop = True

    # ---- TCP connect probe ----
    def _tcp_probe(self, host: str, port: int):
        t0 = time.time()
        state, err = "filtered", ""
        try:
            with socket.create_connection((host, port), self.timeout):
                state = "open"
        except ConnectionRefusedError:
            state = "closed"
        except socket.timeout:
            state = "filtered"
        except OSError as e:
            state, err = "error", str(e)
        lat = int((time.time()-t0)*1000)
        return host, port, {"proto":"tcp","state":state,"latency_ms":lat,"error":err}

    # ---- Scan orchestrator ----
    def scan(self, targets: List[str], ports: List[int],
             do_tcp: bool = True, do_udp: bool = False,
             on_result: Callable[[str,int,Dict[str,Any]], None] = None,
             on_progress: Callable[[int,int], None] = None) -> Dict[str,Any]:

        started = int(time.time()*1000)
        total = max(1, len(targets)*len(ports))
        done = 0
        results: Dict[str, Dict[int, Dict[str,Any]]] = {t:{} for t in targets}
        summaries = []

        futs = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for host in targets:
                for p in ports:
                    if self._stop: break
                    if do_tcp:
                        futs.append(pool.submit(self._tcp_probe, host, p))

            for fut in as_completed(futs):
                if self._stop: break
                try:
                    host, port, info = fut.result()
                except Exception:
                    logging.exception("Worker failure")
                    continue

                results.setdefault(host, {}).setdefault(port, {})["tcp"] = info
                if on_result:
                    on_result(host, port, {"tcp": info})

                done += 1
                if on_progress:
                    on_progress(done, total)

        # simple per-host summary
        for h, ports_map in results.items():
            opens = [p for p,v in ports_map.items() if v.get("tcp",{}).get("state")=="open"]
            filtered = [p for p,v in ports_map.items() if v.get("tcp",{}).get("state")=="filtered"]
            warns = []
            if len(filtered) >= max(5, int(0.5*len(ports_map))):
                warns.append("many TCP timeouts/filtered → possible firewall")
            summaries.append({"host":h, "open_tcp":opens, "warnings":warns})

        ended = int(time.time()*1000)
        return {"started_ms":started, "ended_ms":ended, "targets":targets,
                "results":results, "summaries":summaries}

