#!/usr/bin/python
import sys

class TraceRecord(object):
    def __init__(self, log):
        self.log = log
        self.stack = None

    @classmethod
    def add_extention(cls, arg_parser_name, arg_parser):
        cls.arg_load_map[arg_parser_name] = arg_parser

    def load_args_default(self, args):
        self.args = {}
        for arg in args:
            k,v=arg.split('=')
            key = k.strip()
            try:
                v = v.strip()
                val = int(v,0)
            except ValueError:
                val = v
            self.args[key]=val

    def load_args_stack(self, args):
        if args[0] == '<stack' and args[1] == 'trace>':
            self.args={}
            self.stack = []

    arg_load_map = {
        'kernel_stack': load_args_stack,
    }

    def load_rec(self, a):
        if len(a) < 4:
            raise ValueError('Corrupted event header')

        [proc_s,cpu_s,ts_s,evt_s] = a[0:4]
        p=proc_s.split('-')
        self.proc_name='-'.join(p[0:-1])
        if self.proc_name == '<...>':
            self.proc_name = ''
        self.pid=int(p[-1])
        self.cpu = int(cpu_s[1:-1])
        self.ts = float(ts_s[0:-1])
        self.evt_name = evt_s[0:-1]
        self.pos = self.log.pos()
        self.arg_load_map.get(self.evt_name, TraceRecord.load_args_default)(self, a[4:])
        res = 1 if self.stack != None else 0
        return res

    def load_stack_rec(self, a):
        if a[0] != '=>':
            return -1
        if len(a) == 2 and a[1][0].isdigit():
            name=''
            addr=int(a[1],16)
        elif len(a) == 3:
            name = a[1]
            addr = int(a[2][1:-1],16)
        else:
            raise ValueError('Unrecognized stack trace format')
        self.stack.append((name, addr, self.log.pos()))
        return 1

    # return values:
    # line consumed, not done(1); line consumed, done(0), not consumed(-1)
    def load(self, line):
        a = line.split()
        res = self.load_stack_rec(a) if self.stack != None else self.load_rec(a)
        return res

    def __repr__(self):
        return '%f %d %s %d %s %s %s' % (self.ts, self.cpu, self.proc_name, self.pid, self.evt_name, self.args, self.stack)

class TraceLog(object):
    def __init__(self):
        self.hdr = {}
        self.recs=[]
        self.stack=None
        self.prev = None
        self._pos = -1

    def pos(self):
        return self._pos

    def load_header(self, line):
        if line[0] in ' =': return False
        try:
            k,v = line.split('=')
            key = k.strip()
            val = v.strip()
            self.hdr[key] = val
        except:
            pass
        return True

    def load_rec(self, line):
        rec = TraceRecord(self)
        if rec.load(line):
            self.recs.append(rec)
            return True
        return False

    def load(self, fn, *args, **kwargs):
        self.recs=[]
        with open(fn,'r') as f:
            self._pos = 0
            self.load_file(f, *args, **kwargs)
        return self.recs

    def load_file(self, f, show_lines=None):
        rec = TraceRecord(self)
        prev = None
        if show_lines == None:
            def _show_lines(pos, final=False):
                print 'Parsing: %012d lines\r' % pos,
                sys.stdout.flush()
                if final:
                    print
            show_lines = _show_lines
        for line in f:
            try:
                self._pos += 1
                if self.load_header(line): continue
                res = -1
                while res < 0:
                    res = rec.load(line)
                    if res > 0: continue
                    if rec.stack != None:
                        if prev:
                            prev.stack = rec.stack
                        prev = None
                    else:
                        self.recs.append(rec)
                        prev=rec
                    rec = TraceRecord(self)
            except ValueError, e:
                print >> sys.stderr, e
                print >> sys.stderr, 'In line %d: %s' % (self._pos, line)
                raise
            if self._pos % 1000 == 0:
                show_lines(self._pos)
        show_lines(self._pos, True)
        return self.recs
