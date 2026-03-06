
from typing import List
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unified_types import evaluate_expression_taint,SymbolTable, TaintState, ASTNode, AssignmentNode


class InputDetectionModule:
    """Detects taint sources and updates symbol table"""
    
    TAINT_SOURCES = {
        'input', 'raw_input', 'readLine', 'nextLine',
        'getParameter', 'getQueryString', 'getHeader', 'getCookie',
        'request.getParameter', 'Scanner.nextLine'
    }
    
    SANITIZATION_FUNCTIONS = {
        'sanitize', 'escapeSql', 'prepareStatement'
    }
    
    def __init__(self, symbol_table: SymbolTable):
        self.symbol_table = symbol_table
        self.detected_sources = []
        self.detected_sanitizations = []
    
    def detect_taint_source(self, assignment_node: AssignmentNode) -> bool:
        """Check if assignment introduces tainted data"""
        var_name = assignment_node.variable
        expr = assignment_node.expression
        
        # Check if RHS is a sanitization function
        if self._is_sanitization_function(expr):
            self.symbol_table.set_taint(var_name, TaintState.SANITIZED)
            self.detected_sanitizations.append({
                'variable': var_name,
                'line': assignment_node.line_number,
                'sanitizer': self._get_source_name(expr)
            })
            return False  # Do NOT propagate taint beyond sanitization
        
        if self._is_taint_source(expr):
            self.symbol_table.set_taint(var_name, TaintState.TAINTED)
            self.detected_sources.append({
                'variable': var_name,
                'line': assignment_node.line_number,
                'source': self._get_source_name(expr)
            })
            return True
        
        taint_state = evaluate_expression_taint(expr, self.symbol_table)
        self.symbol_table.set_taint(var_name, taint_state)
        return taint_state == TaintState.TAINTED
    
    def _is_taint_source(self, expr_node: ASTNode) -> bool:
        """Check if expression is a taint source"""
        if expr_node.type != 'FunctionCall':
            return False
        
        if expr_node.function.type == 'Identifier':
            return expr_node.function.name in self.TAINT_SOURCES
        
        if expr_node.function.type == 'MemberAccess':
            return expr_node.function.property.name in self.TAINT_SOURCES
        
        return False
    
    def _is_sanitization_function(self, expr_node: ASTNode) -> bool:
        """Check if expression is a sanitization function"""
        if expr_node.type != 'FunctionCall':
            return False
        
        if expr_node.function.type == 'Identifier':
            return expr_node.function.name in self.SANITIZATION_FUNCTIONS
        
        if expr_node.function.type == 'MemberAccess':
            return expr_node.function.property.name in self.SANITIZATION_FUNCTIONS
        
        return False
    
    def _get_source_name(self, expr_node: ASTNode) -> str:
        """Get source function name"""
        if expr_node.function.type == 'Identifier':
            return expr_node.function.name
        return expr_node.function.property.name
    
    def _analyze_expression_taint(self, expr_node: ASTNode) -> TaintState:
        """Analyze taint state of an expression"""
        if expr_node.type == 'Identifier':
            return self.symbol_table.get_taint(expr_node.name)
        
        elif expr_node.type == 'BinaryExpression':
            left_taint = self._analyze_expression_taint(expr_node.left)
            right_taint = self._analyze_expression_taint(expr_node.right)
            
            if left_taint == TaintState.TAINTED or right_taint == TaintState.TAINTED:
                return TaintState.TAINTED
            return TaintState.UNTAINTED
        
        elif expr_node.type in ['StringLiteral', 'NumberLiteral']:
            return TaintState.UNTAINTED
        
        return TaintState.UNKNOWN