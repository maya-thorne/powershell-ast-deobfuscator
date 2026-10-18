"""
Command-Line Interface (CLI) for PowerShell AST Deobfuscator.
"""

import json
import os
import sys

from .amsi_etw_detector import PowerShellAmsiEtwDetector, detect_amsi_etw, neutralize_amsi_etw
from .amsi_etw_signatures import BUILTIN_SIGNATURES, DEFAULT_RULESET
from .ast_exporter import ASTExporter
from .ast_visualizer import ASTVisualizer
from .benchmark import (
    get_corpus,
    get_corpus_by_category,
    get_sample,
    run_benchmark,
    save_report,
    to_json_report,
    to_markdown_report,
    to_text_report,
)
from .cli_args import build_cli_parser
from .deobfuscator_engine import PowerShellDeobfuscator
from .execution_policy import (
    export_policy_json,
    neutralize_policy_bypasses,
    parse_cli_policy_args,
    simulate_execution_policy,
    to_policy_report,
)
from .lexer import PowerShellLexer
from .parser import PowerShellParser
from .webclient_tracer import carve_all_urls, extract_download_urls, trace_webclient


def main() -> None:
    parser = build_cli_parser()
    args = parser.parse_args()

    # 0. Handle standalone CLI launch argument evaluation mode (--cli-eval)
    if args.cli_eval:
        parsed_cli = parse_cli_policy_args(args.cli_eval)
        output_text = json.dumps(
            {
                "command_line": args.cli_eval,
                "execution_policy": parsed_cli["execution_policy"].value,
                "scope": parsed_cli["scope"].value,
                "has_policy_flag": parsed_cli["has_policy_flag"],
                "is_bypass": parsed_cli["is_bypass"],
                "has_command_flag": parsed_cli["has_command_flag"],
                "has_encoded_flag": parsed_cli["has_encoded_flag"],
                "has_stdin_flag": parsed_cli["has_stdin_flag"],
                "findings": [f.to_dict() for f in parsed_cli["findings"]],
            },
            indent=2,
            ensure_ascii=False,
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] CLI evaluation saved to: {args.output}")
        else:
            print(output_text)
        return

    # Handle benchmark execution mode
    if args.benchmark or args.benchmark_sample or args.benchmark_category:
        if args.benchmark_sample:
            sample = get_sample(args.benchmark_sample)
            if not sample:
                sys.stderr.write(f"[-] Error: Benchmark sample '{args.benchmark_sample}' not found.\n")
                sys.exit(1)
            target_corpus = [sample]
        elif args.benchmark_category:
            target_corpus = get_corpus_by_category(args.benchmark_category)
            if not target_corpus:
                sys.stderr.write(f"[-] Error: Benchmark category '{args.benchmark_category}' not found or empty.\n")
                sys.exit(1)
        else:
            target_corpus = get_corpus()

        benchmark_summary = run_benchmark(corpus=target_corpus)
        if args.benchmark_format == "json":
            report_content = to_json_report(benchmark_summary)
        elif args.benchmark_format == "markdown":
            report_content = to_markdown_report(benchmark_summary)
        else:
            report_content = to_text_report(benchmark_summary)

        if getattr(args, "benchmark_report", None):
            save_report(report_content, args.benchmark_report)
            print(f"[+] Benchmark report ({args.benchmark_format}) saved to: {args.benchmark_report}")
        else:
            print(report_content)
        return

    # Handle AMSI/ETW signatures dump mode
    if args.amsi_signatures:
        signatures_data = [s.to_dict() for s in DEFAULT_RULESET.all_signatures()]
        output_text = json.dumps(signatures_data, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] AMSI/ETW signatures saved to: {args.output}")
        else:
            print(output_text)
        return

    # Check for missing input argument when not in benchmark mode
    if args.input is None:
        parser.print_help()
        return

    # Determine input content
    if os.path.isfile(args.input):
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            script_text = f.read()
    else:
        script_text = args.input

    # 1. Token dump
    if args.tokens:
        lexer = PowerShellLexer(script_text)
        tokens = lexer.tokenize()
        output_text = "\n".join(str(tok) for tok in tokens)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] Token stream saved to: {args.output}")
        else:
            print(output_text)
        return

    # Determine requested AST format
    export_format = args.format
    if args.mermaid:
        export_format = "mermaid"
    elif args.dot:
        export_format = "dot"
    elif args.json:
        export_format = "json"
    elif args.ascii:
        export_format = "ascii"

    is_ast_mode = args.ast or args.tree or (export_format is not None) or args.stats

    # 2. AST visualization / export / stats
    if is_ast_mode:
        lexer = PowerShellLexer(script_text)
        tokens = lexer.tokenize()
        ps_parser = PowerShellParser(tokens)
        ast = ps_parser.parse()

        if args.stats:
            exporter = ASTExporter()
            metrics = exporter.extract_metrics(ast)
            output_text = json.dumps(metrics, indent=2, ensure_ascii=False)
        elif export_format == "mermaid":
            exporter = ASTExporter()
            output_text = exporter.to_mermaid(ast, wrap_markdown=False)
        elif export_format == "dot":
            exporter = ASTExporter()
            output_text = exporter.to_dot(ast)
        elif export_format == "json":
            exporter = ASTExporter()
            output_text = exporter.to_json(ast, indent=2)
        elif export_format == "ascii":
            visualizer = ASTVisualizer(unicode=False)
            output_text = visualizer.render(ast)
        elif export_format == "raw":
            output_text = str(ast)
        else:
            # Default tree format: clean Unicode tree
            visualizer = ASTVisualizer(unicode=True)
            output_text = visualizer.render(ast)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] AST output saved to: {args.output}")
        else:
            print(output_text)
        return

    # 3. Base64 encoded command forensic layers / payload extraction
    if args.layers or args.extract_b64:
        engine = PowerShellDeobfuscator(
            unwrap_subexpr=args.unwrap_subexpr,
            normalize_casing=args.normalize_casing,
        )
        result = engine.deobfuscate(script_text)
        layers = engine.last_layers
        if args.layers:
            layers_data = [
                {
                    "depth": l.depth,
                    "cli_binary": l.cli_binary,
                    "flags": l.flags,
                    "detected_encoding": l.detected_encoding,
                    "entropy_before": l.entropy_before,
                    "entropy_after": l.entropy_after,
                    "b64_payload_preview": l.b64_payload[:40] + ("..." if len(l.b64_payload) > 40 else ""),
                    "decoded_content": l.decoded_content,
                }
                for l in layers
            ]
            output_text = json.dumps(
                {
                    "total_layers": len(layers),
                    "layers": layers_data,
                    "final_script": result,
                },
                indent=2,
                ensure_ascii=False,
            )
        else:
            output_text = layers[-1].decoded_content if layers else result

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] Output saved to: {args.output}")
        else:
            print(output_text)
        return

    # 4. Remote payload URL carving and WebClient cradle analysis
    if args.carve_urls or args.urls:
        engine = PowerShellDeobfuscator(
            unwrap_subexpr=args.unwrap_subexpr,
            normalize_casing=args.normalize_casing,
        )
        deobf_script = engine.deobfuscate(script_text)
        targets = carve_all_urls(deobf_script)
        raw_targets = carve_all_urls(script_text)
        seen_urls = {t.url for t in targets}
        for rt in raw_targets:
            if rt.url not in seen_urls:
                seen_urls.add(rt.url)
                targets.append(rt)

        if args.urls:
            urls_list = sorted({t.url for t in targets if t.is_valid_url})
            output_text = "\n".join(urls_list)
        else:
            output_text = json.dumps([t.to_dict() for t in targets], indent=2, ensure_ascii=False)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] Carved URLs saved to: {args.output}")
        else:
            print(output_text)
        return

    # 5. IEX wrapper layer forensic telemetry dump
    if args.trace_iex:
        engine = PowerShellDeobfuscator(
            unwrap_subexpr=args.unwrap_subexpr,
            normalize_casing=args.normalize_casing,
            unwrap_iex=True,
        )
        deobf_script = engine.deobfuscate(script_text)
        iex_layers = [l.to_dict() for l in engine.last_iex_layers]
        output_text = json.dumps(
            {
                "total_layers": len(iex_layers),
                "is_peeled": len(iex_layers) > 0,
                "layers": iex_layers,
                "final_script": deobf_script,
            },
            indent=2,
            ensure_ascii=False,
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] IEX trace saved to: {args.output}")
        else:
            print(output_text)
        return

    # 5.1 In-memory compressed stream layer forensic telemetry dump
    if args.trace_streams:
        engine = PowerShellDeobfuscator(
            unwrap_subexpr=args.unwrap_subexpr,
            normalize_casing=args.normalize_casing,
            unwrap_iex=args.unwrap_iex,
            decompress_streams=True,
        )
        deobf_script = engine.deobfuscate(script_text)
        stream_layers = [
            {
                "depth": l.depth,
                "compression_type": l.compression_type.value if hasattr(l.compression_type, "value") else str(l.compression_type),
                "compressed_size": l.compressed_size,
                "decompressed_size": l.decompressed_size,
                "compression_ratio": l.compression_ratio,
                "detected_encoding": l.detected_encoding,
                "entropy_before": l.entropy_before,
                "entropy_after": l.entropy_after,
                "raw_expression": l.raw_expression,
                "decompressed_text": l.decompressed_text,
            }
            for l in engine.last_compression_layers
        ]
        output_text = json.dumps(
            {
                "total_layers": len(stream_layers),
                "has_compressed_streams": len(stream_layers) > 0,
                "layers": stream_layers,
                "final_script": deobf_script,
            },
            indent=2,
            ensure_ascii=False,
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] Compressed stream trace saved to: {args.output}")
        else:
            print(output_text)
        return

    # 6. AMSI & ETW bypass signature forensic dump
    if args.detect_amsi:
        detector = PowerShellAmsiEtwDetector()
        findings = detector.detect(script_text)
        engine = PowerShellDeobfuscator(
            unwrap_subexpr=args.unwrap_subexpr,
            normalize_casing=args.normalize_casing,
            unwrap_iex=args.unwrap_iex,
            detect_amsi_etw=True,
        )
        deobf_script = engine.deobfuscate(script_text)
        deobf_findings = detector.detect(deobf_script)

        all_findings = []
        seen = set()
        for f in findings + deobf_findings:
            key = (f.signature_id, f.matched_text.strip())
            if key not in seen:
                seen.add(key)
                all_findings.append(f)

        output_text = json.dumps(
            {
                "has_bypass": len(all_findings) > 0,
                "total_findings": len(all_findings),
                "findings": [f.to_dict() for f in all_findings],
                "deobfuscated_script": deobf_script,
            },
            indent=2,
            ensure_ascii=False,
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] AMSI/ETW findings saved to: {args.output}")
        else:
            print(output_text)
        return

    # 7. Threat hunting rule synthesis (YARA & Sigma)
    if args.generate_yara or args.generate_sigma or args.generate_rules:
        from .rule_models import RuleMetadata, RuleSynthesisOptions
        from .threat_rule_generator import ThreatRuleGenerator

        engine = PowerShellDeobfuscator(
            unwrap_subexpr=args.unwrap_subexpr,
            normalize_casing=args.normalize_casing,
            unwrap_iex=args.unwrap_iex,
            detect_amsi_etw=True,
        )
        deobf_script = engine.deobfuscate(script_text)

        opts = RuleSynthesisOptions(
            target_scope=args.rule_target,
            yara_condition_style=args.yara_condition,
            sigma_logsource=args.sigma_logsource,
        )
        custom_meta = None
        if args.rule_name or args.rule_title:
            custom_meta = RuleMetadata(
                rule_name=args.rule_name or "PowerShell_Threat_Payload_Detected",
                title=args.rule_title or "Suspicious PowerShell Threat Activity",
                description="Auto-synthesized detection rule for PowerShell threat payload.",
            )

        gen = ThreatRuleGenerator()

        if args.generate_rules:
            ruleset = gen.generate_ruleset(
                raw_script=script_text,
                deobfuscated_script=deobf_script,
                metadata=custom_meta,
                options=opts,
            )
            if args.rule_output_dir:
                base_name = args.rule_name or "powershell_threat"
                saved = gen.save_rules(ruleset, args.rule_output_dir, base_name=base_name)
                print(f"[+] YARA rule saved to: {saved['yara']}")
                print(f"[+] Sigma rule saved to: {saved['sigma']}")
            elif args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(ruleset, f, indent=2, ensure_ascii=False)
                print(f"[+] Threat ruleset JSON saved to: {args.output}")
            else:
                print(json.dumps(ruleset, indent=2, ensure_ascii=False))
            return

        if args.generate_yara:
            yara_rule = gen.generate_yara(
                raw_script=script_text,
                deobfuscated_script=deobf_script,
                metadata=custom_meta,
                options=opts,
            )
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(yara_rule)
                print(f"[+] YARA rule saved to: {args.output}")
            else:
                print(yara_rule)
            return

        if args.generate_sigma:
            sigma_rule = gen.generate_sigma(
                raw_script=script_text,
                deobfuscated_script=deobf_script,
                metadata=custom_meta,
                options=opts,
            )
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(sigma_rule)
                print(f"[+] Sigma rule saved to: {args.output}")
            else:
                print(sigma_rule)
            return

    # 7.5. Variable scope and lifecycle analysis
    if args.scope_analysis or args.scope_json or args.export_scope_json:
        from .variable_scope import analyze_scopes, export_scope_json, to_scope_report

        summary = analyze_scopes(script_text)
        if args.scope_json or args.export_scope_json:
            json_text = export_scope_json(summary)
            if args.export_scope_json:
                with open(args.export_scope_json, "w", encoding="utf-8") as f:
                    f.write(json_text + "\n")
                print(f"[+] Scope analysis JSON exported to: {args.export_scope_json}")
            elif args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(json_text + "\n")
                print(f"[+] Scope analysis JSON saved to: {args.output}")
            else:
                print(json_text)
            return

        report = to_scope_report(summary)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report + "\n")
            print(f"[+] Scope analysis report saved to: {args.output}")
        else:
            print(report)
        return

    # 7.6. Runtime ExecutionPolicy simulation & bypass analysis
    if args.policy_analysis or args.policy_json or args.export_policy_json:
        summary = simulate_execution_policy(
            script_text,
            baseline_policy=args.baseline_policy,
            machine_policy=args.machine_policy,
        )
        if args.policy_json or args.export_policy_json:
            json_text = export_policy_json(summary)
            if args.export_policy_json:
                with open(args.export_policy_json, "w", encoding="utf-8") as f:
                    f.write(json_text + "\n")
                print(f"[+] Policy simulation JSON exported to: {args.export_policy_json}")
            elif args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(json_text + "\n")
                print(f"[+] Policy simulation JSON saved to: {args.output}")
            else:
                print(json_text)
            return

        report = to_policy_report(summary)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report + "\n")
            print(f"[+] Policy simulation report saved to: {args.output}")
        else:
            print(report)
        return

    # 8. Default: Full deobfuscation engine
    engine = PowerShellDeobfuscator(
        unwrap_subexpr=args.unwrap_subexpr,
        normalize_casing=args.normalize_casing,
        unwrap_iex=args.unwrap_iex,
        decompress_streams=args.decompress_streams,
        neutralize_amsi_etw=args.neutralize_amsi,
        neutralize_amsi_mode=args.neutralize_mode,
        inline_scoped_vars=args.inline_scoped_vars,
        eliminate_dead_vars=args.eliminate_dead_vars,
        neutralize_policy=args.neutralize_policy,
        neutralize_policy_mode=args.neutralize_policy_mode,
        baseline_policy=args.baseline_policy,
        machine_policy=args.machine_policy,
    )
    result = engine.deobfuscate(script_text)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(result)
        print(f"[+] Deobfuscated script saved to: {args.output}")
    else:
        print(result)


if __name__ == "__main__":
    main()
