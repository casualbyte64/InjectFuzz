import argparse
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any

# Import our Professional Core Modules
from core import (
    PayloadEngine,
    RequestEngine,
    BaselineEngine,
    Analyzer,
    Classifier,
    Payload,
    ResponseData, 
    VulnerabilityLabel,
    MutationType
)
from output.writer import OutputWriter

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="signalfuzz",
        description="SignalFuzz: Behavior-Based Injection Discovery Engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Target Definition
    parser.add_argument("url", help="Target URL (e.g., http://example.com/search?q=test)")
    parser.add_argument("parameter", help="The specific parameter to fuzz (e.g., 'q')")
    parser.add_argument("-m", "--method", choices=["GET", "POST"], default="GET", help="HTTP Method")
    parser.add_argument("-d", "--data", help="POST Data (e.g., 'id=1&user=admin')")

    # Payload Source
    # CHANGE: Removed 'required=True', added 'default' pointing to your specific folder
    parser.add_argument("-f", "--payloads", default="payload/fuzz.txt", help="Path to payload file")
    # Engine Tuning
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrency level")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout (seconds)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    
    # Advanced
    parser.add_argument("--mutate", action="store_true", help="Enable URL-encoding mutations")

    return parser

def prepare_injection(base_params: Dict[str, str], target_param: str, payload: str) -> Dict[str, str]:
    """
    Non-destructively injects the payload into the target parameter.
    Preserves all other parameters (Context Awareness).
    """
    # Create a copy to avoid race conditions in threads
    new_params = base_params.copy()
    
    # If the param exists, overwrite it. If not, add it.
    new_params[target_param] = payload
    return new_params

def fuzz_task(
    payload_obj: Payload,
    request_engine: RequestEngine,
    analyzer: Analyzer,
    classifier: Classifier,
    url: str,
    method: str,
    base_params: Dict,
    base_data: Dict,
    target_param: str
) -> Dict[str, Any]:
    """
    The atomic unit of work for the ThreadPool.
    Executes one payload cycle: Request -> Analyze -> Classify.
    """
    # 1. Prepare Injection
    # We decide where to inject based on Method
    req_params = base_params
    req_data = base_data

    if method == "GET":
        req_params = prepare_injection(base_params, target_param, payload_obj.content)
    elif method == "POST":
        req_data = prepare_injection(base_data, target_param, payload_obj.content)

    # 2. Execute Request
    response = request_engine.send(url, method, req_params, req_data)

    # 3. Analyze Behavior
    # Note: We pass the target_param name so Analyzer can attribute correctly
    analysis = analyzer.analyze(response, payload_obj.content, target_param)

    # 4. Classify Signals
    label = classifier.classify(analysis)

    return {
        "payload": payload_obj.content,
        "category": payload_obj.category,
        "classification": label,
        "analysis": analysis, # Passing full object for writer to parse
        "response_code": response.status_code
    }

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    
    print(f"[*] SignalFuzz Starting...")
    print(f"[*] Target: {args.url}")
    print(f"[*] Parameter: {args.parameter}")

    # 1. Initialization
    try:
        # Init Output Writer
        writer = OutputWriter(args.url, vars(args))
        
        # Init Request Engine
        req_engine = RequestEngine(
            timeout=args.timeout, 
            proxy=args.proxy,
            verify_ssl=False
        )

        # Parse Base Params/Data
        # We need the "clean" state to inject into later
        base_query = urllib.parse.parse_qs(urllib.parse.urlparse(args.url).query)
        # flatten lists from parse_qs: {'q': ['test']} -> {'q': 'test'}
        base_params = {k: v[0] for k, v in base_query.items()}
        
        base_data = {}
        if args.data:
            base_data = dict(urllib.parse.parse_qsl(args.data))

    except Exception as e:
        print(f"[!] Init Failed: {e}")
        sys.exit(1)

    # 2. Baseline Establishment
    print("[*] Calibrating Baseline (this measures server stability)...")
    try:
        bl_engine = BaselineEngine(req_engine)
        baseline = bl_engine.calibrate(args.url, args.method, base_params, base_data)
        
        print(f"    - Stability Score: {baseline.stability_score}/1.0")
        print(f"    - Avg Size: {int(baseline.avg_content_length)} bytes")
        print(f"    - Avg Time: {baseline.avg_response_time:.3f}s")
        
        if baseline.stability_score < 0.5:
            print("[!] WARNING: Target is highly unstable. Results may be noisy.")
            time.sleep(2)

    except Exception as e:
        print(f"[!] Baseline Failed: {e}")
        sys.exit(1)

    # 3. Payload Loading
    try:
        mutations = [MutationType.NONE]
        if args.mutate:
            mutations.append(MutationType.URL)
            
        payload_engine = PayloadEngine(args.payloads, mutations)
        print(f"[*] Payload Source: {args.payloads}")
    except Exception as e:
        print(f"[!] Payload Error: {e}")
        sys.exit(1)

    # 4. Execution Loop (The "Main Event")
    analyzer = Analyzer(baseline)
    classifier = Classifier()
    
    print(f"[*] Starting Scan with {args.threads} threads...")
    
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            # We map futures to payloads but don't store them all to save RAM
            futures = []
            
            # Stream payloads into the executor
            for payload_obj in payload_engine.stream():
                futures.append(executor.submit(
                    fuzz_task,
                    payload_obj,
                    req_engine,
                    analyzer,
                    classifier,
                    args.url,
                    args.method,
                    base_params,
                    base_data,
                    args.parameter
                ))

            # Process results AS THEY FINISH (Non-blocking write)
            count = 0
            for future in as_completed(futures):
                count += 1
                try:
                    result = future.result()
                    label = result['classification']
                    
                    # Console Feedback
                    # We only print if it's NOT "no_issue" to reduce console spam
                    if label == VulnerabilityLabel.POSSIBLE_INJECTION.value:
                        sys.stdout.write(f"\r[!] FOUND INJECTION: {result['payload'][:30]}... \n")
                    elif label == VulnerabilityLabel.ANOMALY.value:
                        sys.stdout.write(f"\r[~] Anomaly: {result['payload'][:30]}... \n")
                    else:
                        # Simple spinner/counter
                        sys.stdout.write(f"\r[*] Processed: {count} | Last Status: {result['response_code']}")

                    # Disk Write (Always write everything or just interesting? 
                    # Prompt requirement implied reporting signals. We write ALL non-clean results usually.
                    # But for audit, we write everything that isn't strict noise.)
                    
                    if label != VulnerabilityLabel.NO_ISSUE.value:
                        # Convert AnalysisResult object to dict for JSON serialization
                        analysis_data = {
                            "classification": result['analysis'].classification.value,
                            "reason": result['analysis'].reason,
                            "diff_score": result['analysis'].diff_score,
                            "response": {
                                "status": result['analysis'].response.status_code,
                                "length": result['analysis'].response.content_length,
                                "time": result['analysis'].response.response_time
                            }
                        }
                        
                        writer.write_finding({
                            "payload": result['payload'],
                            "classification": label,
                            "analysis": analysis_data
                        })

                except Exception as exc:
                    print(f"\n[!] Task Error: {exc}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    
    finally:
        # 5. Finalize
        print("\n")
        writer.finalize()

if __name__ == "__main__":
    main()