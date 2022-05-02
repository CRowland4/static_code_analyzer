import argparse
import os
import re
import ast

parser = argparse.ArgumentParser()
parser.add_argument('path')
args = parser.parse_args()


class StaticCodeAnalyzer:
    def __init__(self):
        self.input_path = ''
        self.file_path = ''
        self.files = []
        self.file_lines = []
        self.line_errors = {
            # <line number>: [list of error messages]
        }
        self.args = args
        self.tree = None

        self.INDENTATION_LENGTH = 4
        self.SPACES_BEFORE_COMMENT = 2
        self.MAX_LINE_LENGTH = 79
        self.MAX_BLANK_LINES = 2

    def main(self):
        self._set_input_path()
        self._set_files()
        self._sort_and_filter_files()

        for path in self.files:
            self.file_path = path
            self._fully_analyze()

    def _fully_analyze(self):
        self._set_file_lines()
        self._set_line_errors()
        self._set_tree()
        self._analyze_line_length()
        self._analyze_indentation_length()
        self._analyze_semi_colons()
        self._analyze_comment_spacing()
        self._find_todos()
        self._analyze_blank_lines()
        self._check_construction()
        self._check_class_names()
        self._check_function_names()
        self._analyze_function_arguments()
        self._analyze_variable_names()
        self._print_errors()

    def _set_input_path(self):
        self.input_path = self.args.path
        return

    def _set_files(self):
        if os.path.isfile(self.input_path):
            self.files.append(self.input_path)
            return
        if os.path.isdir(self.input_path):
            os.chdir(self.input_path)
            self.files = os.listdir(self.input_path)
            return

    def _sort_and_filter_files(self):
        filtered_files = [file for file in self.files if file[-3:] == '.py']
        self.files = sorted(filtered_files)
        return

    def _set_file_lines(self):
        with open(self.file_path, 'r') as file:
            self.file_lines = file.readlines()
        return

    def _set_line_errors(self):
        for i in range(1, max(len(self.file_lines) + 1, len(self.line_errors.keys()) + 1)):
            self.line_errors[i] = []
        return

    def _set_tree(self):
        with open(self.file_path, 'r') as file:
            code = file.read()

        self.tree = ast.parse(code)
        return

    def _analyze_line_length(self):
        for index, line in enumerate(self.file_lines, start=1):
            if len(line.rstrip()) > self.MAX_LINE_LENGTH:
                statement = f'Line {index}: S001 Too long'
                self.line_errors[index].append(statement)
        return

    def _analyze_indentation_length(self):
        for index, line in enumerate(self.file_lines, start=1):
            if line.strip() and (len(line) - len(line.lstrip())) % self.INDENTATION_LENGTH != 0:
                statement = f'Line {index}: S002 Indentation is not a multiple of four'
                self.line_errors[index].append(statement)
        return

    def _analyze_semi_colons(self):
        for index, line in enumerate(self.file_lines, start=1):
            if ';' in line and '#' not in line[:line.index(';')] and not self._semicolon_in_string(line):
                statement = f'Line {index}: S003 Unnecessary semicolon'
                self.line_errors[index].append(statement)
        return

    def _semicolon_in_string(self, line):
        before_semicolon = line[:line.index(';')]
        after_semicolon = line[line.index(';'):]

        if "'" in before_semicolon and "'" in after_semicolon:
            return True
        if '"' in before_semicolon and '"' in after_semicolon:
            return True

        return False

    def _analyze_comment_spacing(self):
        for index, line in enumerate(self.file_lines, start=1):
            if '#' in line[3:] and line[line.index('#') - self.SPACES_BEFORE_COMMENT:line.index('#')] != '  ':
                statement = f'Line {index}: S004 At least two spaces required before inline comments'
                self.line_errors[index].append(statement)
        return

    def _find_todos(self):
        for index, line in enumerate(self.file_lines, start=1):
            if 'todo' in line.lower()[line.find('#'):]:
                statement = f'Line {index}: S005 TODO found'
                self.line_errors[index].append(statement)
        return

    def _analyze_blank_lines(self):
        for index, line in enumerate(self.file_lines, start=1):
            check_1 = index >= 4  # Makes sure there are at least 3 previous lines to check. Let's the index start at 1.
            check_2 = line.strip()  # Ensures that only non-blank lines are checked for too many preceding blank lines.
            check_3 = self.file_lines[self.file_lines.index(line) - 3:self.file_lines.index(line)] == ['\n', '\n', '\n']
            #  The above check determines if there are 3 blank lines preceding the current line.

            if all([check_1, check_2, check_3]):
                statement = f'Line {index}: S006 More than two blank lines used before this line'
                self.line_errors[index].append(statement)

        return

    def _check_construction(self):
        for index, line in enumerate(self.file_lines, start=1):
            if 'def' in line and line[line.find('def') + 3:line.find('def') + 5] == '  ':
                statement = f"Line {index}: S007 Too many spaces after 'def'"
                self.line_errors[index].append(statement)
            if 'class' in line and line[line.find('class') + 5:line.find('class') + 7] == '  ':
                statement = f"Line {index}: S007 Too many spaces after 'class'"
                self.line_errors[index].append(statement)

        return

    def _check_class_names(self):
        for index, line in enumerate(self.file_lines, start=1):
            if 'class' not in line:
                continue

            line_without_whitespace = ''
            for char in line:
                if not re.match(r'[\s]', char):
                    line_without_whitespace += char

            class_name = line_without_whitespace[line_without_whitespace.index('class') + 5:-1]
            if '(' in class_name:
                class_name = class_name[:class_name.index('(')]

            if class_name == class_name.lower() or '_' in class_name:  # This passed, but I don't like it
                statement = f'Line {index}: S008 Class name {class_name} should use CamelCase'
                self.line_errors[index].append(statement)

        return

    def _check_function_names(self):
        for index, line in enumerate(self.file_lines, start=1):
            if 'def' not in line:
                continue

            line_without_whitespace = ''
            for char in line:
                if not re.match(r'[\s]', char):
                    line_without_whitespace += char

            function_name = line_without_whitespace[line_without_whitespace.index('def') + 3:]
            if '(' in function_name:
                function_name = function_name[:function_name.index('(')]

            if function_name != function_name.lower():  # This passed too, but I don't like it either
                statement = f'Line {index}: S009 Function name {function_name} should use snake_case'
                self.line_errors[index].append(statement)

        return

    def _analyze_function_arguments(self):
        function_def_nodes = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                function_def_nodes.append(node)

        for function_def_node in function_def_nodes:
            for arg in function_def_node.args.args:
                if arg.arg != arg.arg.lower():
                    line_number = function_def_node.lineno
                    statement = f'Line {line_number}: S010 Argument name {arg.arg} should be written in snake_case'
                    self.line_errors[line_number].append(statement)

            for node in function_def_node.args.defaults:
                if isinstance(node, ast.List) or isinstance(node, ast.Dict):
                    line_number = function_def_node.lineno
                    statement = f'Line {line_number}: S012 The default argument value is mutable'
                    self.line_errors[line_number].append(statement)

        return

    def _analyze_variable_names(self):
        variable_nodes = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                variable_nodes.append(node)

        for variable_node in variable_nodes:
            if variable_node.id != variable_node.id.lower():
                line_number = variable_node.lineno
                statement = f'Line {line_number}: S011 Variable {variable_node.id} should be written in snake_case'
                self.line_errors[line_number].append(statement)

        return

    def _print_errors(self):
        all_errors = []
        for error_list in self.line_errors.values():
            all_errors += error_list

        all_errors.sort(key=lambda x: int(x[5:x.index(':')]))  # Sorts by the line number

        if os.path.isfile(self.input_path):
            for error in all_errors:
                print(f'{self.input_path}: {error}')
        elif os.path.isdir(self.input_path):
            for error in all_errors:
                print(f'{self.input_path}{os.sep}{self.file_path}: {error}')

        return


stage_1 = StaticCodeAnalyzer()
stage_1.main()
