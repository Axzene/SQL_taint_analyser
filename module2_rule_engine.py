"""Module 2: Rule Engine - Detects SQL injection vulnerabilities"""

from typing import Optional, Dict
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unified_types import SymbolTable, TaintState, ASTNode, FunctionCallNode, VulnerabilityEvent


class RuleEngineModule:
    """Applies vulnerability detection rules"""
    
    SQL_SINKS = {'execute', 'executeQuery', 'executeUpdate', 'query', 'exec'}
    
    def __init__(self, symbol_table: SymbolTable):
        self.symbol_table = symbol_table
        self.detected_vulnerabilities = []
        self.vuln_counter = 0
    
    def apply_detection_rules(self, node: FunctionCallNode) -> Optional[VulnerabilityEvent]:
        """Apply core vulnerability detection rule"""
        if not self._is_sql_sink(node):
            return None
        
        if not hasattr(node, 'arguments') or len(node.arguments) == 0:
            return None
        
        query_arg = node.arguments[0]
        
        # Check for parameterized query
        if len(node.arguments) >= 2 and self._has_placeholders(query_arg):
            return None
        
        # Check for tainted data
        is_vulnerable, taint_info = self._check_vulnerability_condition(query_arg)
        if not is_vulnerable:
            return None
        
        construction = self._analyze_construction(query_arg)
        rule_explanation = self._get_rule_explanation(construction)
        
        # Severity differentiation: concat → HIGH, format → MEDIUM
        severity = 'HIGH' if construction == 'string_concatenation' else 'MEDIUM'
        
        self.vuln_counter += 1
        vulnerability = VulnerabilityEvent(
            vulnerability_id=f"SQLI-{self.vuln_counter:04d}",
            line_number=node.line_number,
            file_path=node.file_path,
            function_name=self._get_function_name(node),
            variable_name=taint_info.get('variable', 'unknown'),
            sink_type=self._get_sink_type(node),
            query_construction=construction,
            severity=severity,
            description=f"{rule_explanation}. Variable '{taint_info.get('variable', 'unknown')}' "
                       f"is tainted and flows to SQL sink '{self._get_sink_type(node)}'. "
                       f"Use parameterized queries to prevent SQL injection.",
            confidence=0.95
        )
        
        self.detected_vulnerabilities.append(vulnerability)
        return vulnerability
    
    def _is_sql_sink(self, node: FunctionCallNode) -> bool:
        """Check if this is an SQL sink"""
        if node.function.type == 'Identifier':
            return node.function.name in self.SQL_SINKS
        if node.function.type == 'MemberAccess':
            return node.function.property.name in self.SQL_SINKS
        return False
    
    def _has_placeholders(self, node: ASTNode) -> bool:
        """Check for SQL parameter placeholders"""
        if node.type == 'StringLiteral':
            return any(ph in node.value for ph in ['?', ':param', '%s', '$1'])
        return False
    
    def _check_vulnerability_condition(self, query_node: ASTNode) -> tuple:
        """Check if query contains tainted data"""
        taint_info = {}
        
        if query_node.type == 'Identifier':
            var_name = query_node.name
            taint_state = self.symbol_table.get_taint(var_name)
            
            if taint_state == TaintState.TAINTED:
                taint_info['variable'] = var_name
                return True, taint_info
        
        elif query_node.type == 'BinaryExpression':
            left_vuln, left_info = self._check_vulnerability_condition(query_node.left)
            right_vuln, right_info = self._check_vulnerability_condition(query_node.right)
            
            if left_vuln or right_vuln:
                taint_info.update(left_info)
                taint_info.update(right_info)
                return True, taint_info
        
        return False, {}
    
    def _analyze_construction(self, query_node: ASTNode) -> str:
        """Analyze how query is constructed"""
        if query_node.type == 'BinaryExpression':
            if query_node.operator == '+':
                return 'string_concatenation'
            elif query_node.operator == '%':
                return 'format_string'
        
        if query_node.type == 'FunctionCall':
            if query_node.function.type == 'MemberAccess':
                if query_node.function.property.name == 'format':
                    return 'format_string'
        
        return 'direct_variable'
    
    def _get_rule_explanation(self, construction: str) -> str:
        """Get detailed rule explanation based on construction type"""
        explanations = {
            'string_concatenation': "Tainted data flows into SQL sink via string concatenation",
            'format_string': "Tainted data flows into SQL sink via format string",
            'direct_variable': "Tainted data flows directly into SQL sink"
        }
        return explanations.get(construction, "Tainted data flows into SQL sink")
    
    def _get_function_name(self, node: FunctionCallNode) -> str:
        """Extract function name"""
        if node.function.type == 'Identifier':
            return node.function.name
        return node.function.property.name
    
    def _get_sink_type(self, node: FunctionCallNode) -> str:
        """Extract sink type"""
        if node.function.type == 'MemberAccess':
            obj_name = getattr(node.function.object, 'name', 'object')
            method_name = node.function.property.name
            return f"{obj_name}.{method_name}"
        return self._get_function_name(node)