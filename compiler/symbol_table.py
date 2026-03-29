class Symbol:
    def __init__(self, name, sym_type, scope, line):
        self.name = name
        self.type = sym_type
        self.scope = scope
        self.line = line
        self.initialized = False
        self.initial_value = None
        self.is_secret = False
        self.is_constant = False
        self.data_flow_source = None  # Taint tracking

    def __repr__(self):
        secret_marker = " [SECRET]" if self.is_secret else ""
        return f"Symbol({self.name}: {self.type}{secret_marker})"


class SymbolTable:
    def __init__(self):
        self.scopes = [{}]  # Stack of scopes
        self.current_scope = 0
        self.all_symbols = []

    def enter_scope(self):
        self.scopes.append({})
        self.current_scope += 1

    def exit_scope(self):
        if len(self.scopes) > 1:
            self.scopes.pop()
            self.current_scope -= 1

    def add(self, name, sym_type, line):
        if name in self.scopes[self.current_scope]:
            return False  # Already defined in this scope
        
        symbol = Symbol(name, sym_type, self.current_scope, line)
        self.scopes[self.current_scope][name] = symbol
        self.all_symbols.append(symbol)
        return True

    def lookup(self, name):
        for scope_idx in range(self.current_scope, -1, -1):
            if name in self.scopes[scope_idx]:
                return self.scopes[scope_idx][name]
        return None

    def mark_as_secret(self, name):
        symbol = self.lookup(name)
        if symbol:
            symbol.is_secret = True
            return True
        return False

    def is_secret(self, name):
        symbol = self.lookup(name)
        return symbol.is_secret if symbol else False

    def get_all_secrets(self):
        return [s for s in self.all_symbols if s.is_secret]

    def display(self):
        result = "\n=== SYMBOL TABLE ===\n"
        for scope_level, scope in enumerate(self.scopes):
            result += f"\nScope {scope_level}:\n"
            for name, symbol in scope.items():
                result += f"  {symbol}\n"
        return result