#!/usr/bin/python
import sys
import ftrace

# extentions to ftrace: my own LMK trace point
def load_args_lmk(self, args):
    self.args = {}
    self.args['nr'] = int(args[0][:-1].split('=')[1])
    self.args['gfp'] = int(args[1][:-1].split('=')[1],16)
    self.args['ofree'] = int(args[3])
    self.args['vfs_cache'] = int(args[4][0:-1])
    self.args['oom_adj'] = int(args[6])

ftrace.TraceRecord.add_extention('lmk_shrink', load_args_lmk)

def report_kswapd(recs):
    print 'Building kswapd report:',
    sys.stdout.flush()
    kswapd=[]
    for rec in filter(lambda rec: rec.evt_name.startswith('mm_vmscan_kswapd_'), recs):
        on=0
        evt_name=rec.evt_name[17]
        if evt_name == 'w':
            on=1
        elif evt_name != 's':
            print 'Line %d: MM event ignored: %s' % (cnt, line)
            continue
        kswapd.append((rec, on))
    print '%d records' % len(kswapd)
    return kswapd

def report_lmk(recs):
    print 'Building LMK report: ',
    sys.stdout.flush()
    lmk=[]
    for rec in  filter(lambda rec: rec.evt_name == 'lmk_shrink', recs):
        args = rec.args
        lmk.append((rec, args['nr'], args['ofree'], args['vfs_cache'], args['oom_adj']))
    print '%d records' % len(lmk)
    return lmk

def report_ofree(recs, ofree_init=0):
    print 'Building MM page report:',
    sys.stdout.flush()
    ofree=[]
    pages={}
    ofree_mm = ofree_init
    for rec in filter(lambda rec: rec.evt_name.startswith('mm_page_'), recs):
        name = rec.evt_name[8:]
        args = rec.args
        addr = args['page']
        if addr == '(nil)':
            addr = 0
        delta = 0
        if name == 'alloc' or name == 'alloc_extfrag' or name == 'alloc_zone_locked':
            allocated = pages.get(addr, None)
            if allocated == None or allocated == False:
                pages[addr] = True
                delta = -1
        elif name == 'free' or name == 'free_batched' or name == 'pcpu_drain':
            allocated = pages.get(addr, None)
            if allocated == None or allocated == True:
                pages[addr] = False
                delta = 1
        if delta == 0:
            continue
        order = args.get('order', None)
        if order == None:
            order = args.get('alloc_order',None)
            if order == None:
                print 'Unknown alloc order on page addr %08X, line %d' % (addr, n_line)
                continue
        n_pages = 1 << order
        ofree_mm += (n_pages * delta)
        ofree.append((rec, ofree_mm))
    print '%d records; %d pages' % (len(ofree), len(pages))
    return ofree

def report_page_history(recs):
    pages={}
    for rec in recs:
        evt_name = rec.evt_name
        n_line = rec.pos
        args = rec.args
        if not evt_name.startswith('mm_page_'): continue
        page = args.get('page', None)
        addr = 0 if page == None or page == '(nil)' else page
        page = pages.get(addr, [])
        order = args.get('order', None)
        if order == None:
            order = args.get('alloc_order',None)
            if order == None:
                print 'Unknown alloc order on page addr %08X, line %d' % (addr, n_line)
                continue
        if len(page) == 0:
            pages[addr] = page
        page.append((rec, 1 << order))
    return pages

def adjust_ofree(ofree_recs, lmk_recs, pts=1, offset=0):
    if pts <= 0: pts = 1
    if pts > len(lmk_recs): pts = len(lmk_recs)
    print 'Looking for the best adjustment value for ofree out of at most %d lmk samples' % pts
    lmk_diff = []
    cnt = 0
    for rec, _, lmk_ofree, _, _ in lmk_recs:
        cnt+= 1
        lmk_ts = rec.ts
        delta = 1
        found = None
        for r in filter(lambda x: abs(x[0].ts - lmk_ts) < 0.001, ofree_recs):
            ofree_ts = r[0].ts
            diff = abs(ofree_ts - lmk_ts)
            if diff < delta:
                delta = diff
                found = r
        if found != None:
            lmk_diff.append((found, (rec, lmk_ofree)))
        if cnt >= pts: break
    adj = 0
    for ofree_rec, lmk_rec in lmk_diff:
        adj += lmk_rec[1] - ofree_rec[1]
    if cnt:
        adj = int(float(adj)/float(cnt))
        print 'Applying selected adjustment value: %d' % adj
    else:
        adj = offset
        print 'no LMK data; using default adjustment: %d' % adj

    for i in xrange(len(ofree_recs)):
        rec, ofree = ofree_recs[i]
        ofree_recs[i] = (rec, ofree + adj)

def save_kswapd(kswapd_recs, fn_out):
    with open(fn_out, 'w') as fout:
        for rec, val in kswapd_recs:
            fout.write('%f, %d\n' % (rec.ts, val))

def save_lmk(lmk_recs, fn_out):
    with open(fn_out, 'w') as fout:
        for rec, nr, ofree, vfs_cache, oom_adj in lmk_recs:
            fout.write('%f, %d, %d, %d, %d\n' % (rec.ts, nr, ofree, vfs_cache, oom_adj))

def save_ofree(ofree_recs, fn_out):
    with open(fn_out, 'w') as fout:
        for rec, ofree in ofree_recs:
            fout.write('%f, %d\n' % (rec.ts, ofree))

def save_page_history(pages, fn_out):
    with open(fn_out, 'w') as fout:
        for addr in sorted(pages):
            hist = pages[addr]
            fout.write('%08X: %s\n' % (addr, ','.join('(%s, %d, %d)' % (rec.evt_name, rec.pos, order) for rec, order in hist )))

def main(argv):
    # handle cmd-line args
    want_hist = False
    my_name = None
    fname = None
    pfx = None
    csv_out = True
    raw_dump = False
    for arg in argv:
        if arg == '--hist':
            want_hist = True
        elif arg == '--dump':
            raw_dump = True
        elif arg == '--nocsv':
            csv_out = False
        elif my_name == None:
            my_name = arg
        elif fname == None:
            fname = arg
        elif pfx == None:
            pfx = arg
        else:
            print 'unexpected arg:', arg
    if fname == None:
        fname = 'trace.dat.txt'
    if pfx == None:
        pfx = fname.split('.')[0]

    # load trace points
    print 'Processing: %s' % fname
    log = ftrace.TraceLog()
    recs = log.load(fname)

    if raw_dump:
        fn = '%s_raw.log' % pfx
        print 'Dumping parsed records to: %s' % fn
        with open(fn, 'w') as fout:
            for rec in recs:
                print >>fout, rec

    # process data
    if csv_out:
        print 'Processing data'
        kswapd = report_kswapd(recs)
        lmk = report_lmk(recs)
        ofree = report_ofree(recs)
        adjust_ofree(ofree, lmk, pts=10, offset=15000)

        print 'Generating outputs'
        save_kswapd(kswapd, '%s_kswapd.csv' % pfx)
        save_lmk(lmk, '%s_lmk.csv' % pfx)
        save_ofree(ofree, '%s_ofree.csv' % pfx)

    if want_hist:
        print 'Generating per-page trace history'
        pages = report_page_history(recs)
        save_page_history(pages, '%s_mm_hist.log' % pfx)

    print 'Done'

if __name__ == '__main__':
    main(sys.argv)
