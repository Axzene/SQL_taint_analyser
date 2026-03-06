# SQL_taint_analyser
Static SQL Injection Detection Using Compiler-Based Taint Analysis

Static SQL Injection Detection using Compiler Techniques

## Overview
This project implements a static analysis tool for detecting SQL Injection vulnerabilities using compiler design techniques. The system analyzes source code without executing it and identifies unsafe SQL query constructions where untrusted user input flows into SQL queries without proper sanitization.

The tool uses taint analysis to track how input data propagates through variables and expressions in a program.

## Project Structure

main.py  
Entry point of the analysis pipeline.

unified_types.py  
Defines shared structures such as SymbolTable, TaintState, AST nodes, and helper functions used across modules.

ast_bridge.py  
Converts parsed AST nodes into the internal structures used by the analysis modules.

ast_traverser.py  
Traverses the AST and sends relevant nodes to the analysis modules.

module1_input_detection.py  
Detects taint sources such as user input functions.

module2_*  
Handles taint propagation through program variables and expressions.

module3_*  
Performs vulnerability detection and generates warnings.

demo_programs/  
Contains example programs used for testing the analysis system:
- sample_target.py (vulnerable program)
- sample_mixed.py (mixed safe and unsafe patterns)
- sample_safe.py (properly sanitized program)

## How to Run

1. Clone the repository

git clone <repository-url>

2. Navigate to the project directory

cd <project-folder>

3. Run the analyzer

python main.py

## Purpose
This project demonstrates how compiler design concepts such as Abstract Syntax Trees (AST), symbol tables, and program traversal can be used to perform static security analysis and detect potential SQL injection vulnerabilities.
