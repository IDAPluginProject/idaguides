import ida_hexrays
import ida_idaapi
import idaapi

INDENTN = 4  # should match 'Block indent' in decompiler settings
ICHAR = "│"

GAPST = " " * INDENTN
FLINE = ICHAR + " " * (INDENTN - 1)
NLINE = bytes.fromhex("01").decode() + bytes.fromhex("04").decode() + FLINE
COLORB = bytes.fromhex("01").decode()
COLORG = bytes.fromhex("04").decode()
LASTCOLRANGE = set()
HIGHLIGHTED = False

lines = []


def count_indent(line):
    lvl = 0
    s = line.find(GAPST)
    if s != -1:
        lvl += 1
        line = line[s + INDENTN :]
        while True:
            s = line.find(GAPST)
            if s != -1 and s == 0:
                lvl += 1
                line = line[INDENTN:]
            else:
                count_indent.last_indent = lvl
                return lvl
    return getattr(count_indent, "last_indent", 0)


def draw_lines(vu):
    global lines
    lines = vu.cfunc.get_pseudocode()
    start = False
    for line in lines:
        if "{" in line.line:
            start = True
        if not start:
            continue
        indent = count_indent(line.line)
        line.line = line.line.replace(GAPST, NLINE, indent)
        line.line = line.line.replace(FLINE, GAPST, 1)


def find_closing_brace(curpos):
    global lines
    cind = lines[curpos].line.count(FLINE)
    for i, line in enumerate(lines):
        if i < curpos:
            continue
        if "}" in line.line and line.line.count(FLINE) == cind:
            return i
    return -1


def find_opening_brace(curpos):
    global lines
    cind = lines[curpos].line.count(FLINE)
    for i, line in enumerate(reversed(lines)):
        rpos = len(lines) - 1 - i
        if rpos > curpos:
            continue
        if "{" in line.line and line.line.count(FLINE) == cind:
            return rpos
    return -1


def colorize_indent(startln, endln):
    global LASTCOLRANGE, COLORB, HIGHLIGHTED
    global lines
    p = -1
    for i, line in enumerate(lines):
        if i >= endln:
            return
        if i <= startln:
            continue
        if ICHAR not in line.line:
            continue
        cind = lines[startln].line.count(FLINE) + 1
        tmp = list(line.line)
        p = -1
        for i in range(cind):
            p = tmp.index(ICHAR, p + 1)
        tmp[p - 1] = COLORB
        line.line = "".join(tmp)
        LASTCOLRANGE = (startln, endln)
        HIGHLIGHTED = True


def clear_highlight():
    global LASTCOLRANGE, HIGHLIGHTED
    global lines
    for i, line in enumerate(lines):
        if i <= LASTCOLRANGE[0]:
            continue
        if i >= LASTCOLRANGE[1]:
            return
        line.line = line.line.replace(COLORB + ICHAR, COLORG + ICHAR)
        HIGHLIGHTED = False


class IDAGuides(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        super().__init__()

    def text_ready(self, vu):
        draw_lines(vu)
        return 0

    def curpos(self, vu):
        global HIGHLIGHTED
        global lines
        curpos = vu.cpos.lnnum
        if "{" in lines[curpos].line:
            endpos = find_closing_brace(curpos)
            if endpos != -1:
                vu.refresh_ctext()
                colorize_indent(curpos, endpos)
        elif "}" in lines[curpos].line:
            opos = find_opening_brace(curpos)
            if opos != -1:
                vu.refresh_ctext()
                colorize_indent(opos, curpos)
        elif HIGHLIGHTED:
            vu.refresh_ctext()
            clear_highlight()
        return 0


class IDAGuides_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "IDAGuides"
    wanted_hotkey = ""
    comment = "Draw indent guides in Hex-Rays decompiler"
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
    return IDAGuides_plugin_t()
