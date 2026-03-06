"""
AST Traverser and Pass Controller (Phase 3)

Responsible for:
- Traversing the AST
- Executing analysis passes in correct order
- Delegating logic to analysis modules

Does NOT implement:
- Taint propagation rules
- SQL detection rules
- Warning decisions
"""

from unified_types import ASTNode, compute_taint_flow
from module1_input_detection import InputDetectionModule
from module2_rule_engine import RuleEngineModule
from module3_warning_logic import WarningDecisionLogic


class ASTTraverser:
    """
    Controls AST traversal and analysis passes.
    """

    def __init__(
        self,
        input_detector: InputDetectionModule,
        rule_engine: RuleEngineModule,
        warning_logic: WarningDecisionLogic,
        symbol_table
    ):
        self.input_detector = input_detector
        self.rule_engine = rule_engine
        self.warning_logic = warning_logic
        self.symbol_table = symbol_table

        self.stats = {
            'taint_sources': 0,
            'sql_sinks': 0,
            'vulnerabilities': 0,
            'safe_patterns': 0
        }

    # =========================
    # PUBLIC ENTRY POINT
    # =========================

    def analyze(self, ast_root: ASTNode):
        """Run all analysis passes on the AST"""

        self._pass1_detect_taint_sources(ast_root)
        self._pass2_detect_vulnerabilities(ast_root)

        return self.stats

    # =========================
    # PASS 1: INPUT / TAINT
    # =========================

    def _pass1_detect_taint_sources(self, node: ASTNode):
        if node.type == 'AssignmentStatement':
            if self.input_detector.detect_taint_source(node):
                self.stats['taint_sources'] += 1

        for child in node.children:
            self._pass1_detect_taint_sources(child)

    # =========================
    # PASS 2: SQL SINKS
    # =========================

    def _pass2_detect_vulnerabilities(self, node: ASTNode):
        if node.type == 'FunctionCall':
            if self.rule_engine._is_sql_sink(node):
                self.stats['sql_sinks'] += 1

                vulnerability = self.rule_engine.apply_detection_rules(node)

                if vulnerability:
                    # Attach taint flow (Member B responsibility)
                    vulnerability.taint_flow = compute_taint_flow(
                        node.arguments[0],
                        self.symbol_table
                    )

                    should_warn = self.warning_logic.process_vulnerability(vulnerability)
                    if should_warn:
                        self.stats['vulnerabilities'] += 1
                else:
                    self.stats['safe_patterns'] += 1

        for child in node.children:
            self._pass2_detect_vulnerabilities(child)
