import ida_hexrays
import ida_idaapi
import idaapi
import re

INDENTN = 4
ICHAR = "│"
INIT_CHAR = "\x01"
COLOR_GRAY = "\x04"
GAPST = " " * INDENTN
FLINE = ICHAR + " " * (INDENTN - 1)
NLINE = INIT_CHAR + COLOR_GRAY + FLINE

BRACE_OPEN = "{"; BRACE_CLOSE = "}"
STAT_IF = "if"; STAT_DO = "do"; STAT_ELSE = "else"
STAT_SW_CASE = "case"; STAT_SW_DEFAULT = "default"
STATEMENTS = [STAT_IF, STAT_DO, STAT_ELSE, STAT_SW_CASE, STAT_SW_DEFAULT]


def make_calc_adjustment():
    check_next = False
    last_indent = 0
    adjustment = 0
    sw_adjustment = 0
    
    def hasStatement(string):
        for stat in STATEMENTS:
            if bool(re.search(rf"\b{re.escape(stat)}\b", string)) == True:
                return stat
        return False

    def calc_adjustment(line):
        nonlocal check_next, last_indent, adjustment, sw_adjustment
        if check_next:
            if not BRACE_OPEN in line.line:
                adjustment += 1
            check_next = False
        elif statement := hasStatement(line.line):
            if statement == STAT_SW_CASE:
                sw_adjustment += 1
            elif statement == STAT_SW_DEFAULT:
                sw_adjustment -= 1 if sw_adjustment else 0
            last_indent = line.line.count(GAPST)
            adjustment = 0
            check_next = True
        elif adjustment > 0:
            if last_indent == line.line.count(GAPST):
                adjustment = 0
        return adjustment + sw_adjustment

    return calc_adjustment


def draw_lines(vu):
    indent_stack = 0
    calc_adjustment = make_calc_adjustment()
    for line in vu.cfunc.get_pseudocode():
        adjustment = calc_adjustment(line)
        if BRACE_OPEN in line.line:
            indent_stack += 1
        elif BRACE_CLOSE in line.line:
            indent_stack -= 1
        if indent_stack <= 0 and adjustment == 0:
            continue
        line.line = line.line.replace(GAPST, NLINE, indent_stack + adjustment)
        line.line = line.line.replace(FLINE, GAPST, 1)


class IDAGuides(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        super().__init__()

    def text_ready(self, vu):
        draw_lines(vu)
        return 0

    def open_pseudocode(self, vu):
        draw_lines(vu)
        return 0


class IDAGuides_Plugin(ida_idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    wanted_name = "IDAGuides"
    wanted_hotkey = ""
    comment = "Draw Indent Guides in Hex-Rays Decompiler"
    help = ""

    def init(self):
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        self.hook = IDAGuides()
        self.hook.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return IDAGuides_Plugin()
