#!/usr/bin/env python2.7
"""
Convert PasswordWallet export files to 1Password 1pif format.

    Usage: PasswordWalletConverter.py <txt_export> <html_export>

To use, you must export your PasswordWallet twice:

    1. File > Export > Visible entries to text file...

       Save the file to your Desktop.

    2. File > Export > to Stand-alone encrypted web pages...

       Split up into multiple pages with...  Don't split up
       Split up each page into groups with... Don't split up
       Display font: helvetica, arial, sans-serif
       Display font size: Small(+0)
       [ ] Export pages as raw bookmarklets
       [ ] Automatically export when this file is closed

       Then click Export and save the file to your Desktop.

Feed both files into this program:

    ./PasswordWalletConverter.py ~/Desktop/PasswordWallet*

This will create `data.1pif` in the current directory, which may
be imported by 1Password.

When done, securely erase both PasswordWallet exports and `data.1pif`
by placing in the Trash and using Finder > Secure Empty Trash.

You may wish to disable any backup programs from running until you're
done so that the unencrypted files don't get backed up.
"""

import sys
import simplejson as json
import uuid
import re
import time
import blowfish
import getpass
from datetime import datetime
from collections import namedtuple, OrderedDict
from bs4 import BeautifulSoup

Record = namedtuple(
    "Record", """
    title url username password notes category browser
    username_type password_type f10
    last_accessed last_modified
    """)

class RecordDict(OrderedDict):
    def __getattr__(self, key):
        if key in self:
            return self[key]
        raise AttributeError(key)

def blowfish_initialize():
    while True:
        pwt = getpass.getpass()
        blowfish.Blowfish_initialize(pwt)
        verify = blowfish.Blowfish_decipher_array([0,0xc1a9741e,0x5b2177a0])
        if "091827" == verify:
            break
        print "Password incorrect!"

def blowfish_decipher_array(rec):
    vals = [int(v, 16) for v in rec.split(",")]
    # blowfish.Blowfish_initialize(PASSWORD)
    return blowfish.Blowfish_decipher_array(vals)

def parse_date(s):
    # 5/31/13
    dt = datetime.strptime(s, "%m/%d/%y")
    return time.mktime(dt.timetuple())

def parse_html_record(html):
    soup = BeautifulSoup(html)
    re_date = re.compile(r"Accessed: ([0-9/]+), Modified: ([0-9/]+)")
    title = soup.h3.extract()
    title.span.decompose()
    rv = RecordDict(title=title.get_text(strip=True))
    for row_num, row in enumerate(soup.table.find_all("tr")):
        cols = row.find_all("td")
        if cols[0].get("class", [None])[0] == "fieldtitle":
            key = cols[0].text.rstrip(':').lower()
        else:
            key = None
        sep = "\n" if key == "notes" else ""
        val = cols[1].get_text(sep, strip=True)
        if key is None:
            m = re_date.search(val)
            if m:
                rv["last_accessed"] = parse_date(m.group(1))
                rv["last_modified"] = parse_date(m.group(2))
                continue
            key = row_num
            # fall through
        elif key == "username":
            val = val.replace(u"\u221e", "")
        rv[key] = val
    return rv

def read_html_input(path):
    rv = {}
    re_record = re.compile(r"gRecord = \[([^\]]+)\];")
    with open(path) as f:
        recs = [m.group(1) for m in (re_record.search(line) for line in f) if m]
    for rec in recs:
        rec = parse_html_record(blowfish_decipher_array(rec))
        assert rec.title not in rv, rec.title
        rv[rec.title] = rec
    return rv

def read_text_input(path):
    rv = {}
    with open(path) as f:
        for line in f:
            fields = [f.decode("utf-8") for f in line.rstrip("\n").split("\t")]
            fields.extend([None, None]) # last_accessed and last_modified
            rec = Record._make(fields)
            rec = rec._replace(
                notes=rec.notes.replace(u"\u00ac", "\n"),
                username=rec.username.replace(u"\u221e", ""),
                username_type=(rec.username_type or "username").lower(),
                password_type=(rec.password_type or "password").lower(),
            )
            assert rec.title not in rv, rec.title
            rv[rec.title] = rec
    return rv

def to_1pif(recs):
    # sep = "***%s***" % uuid.uuid4()
    sep = "***5642bee8-a5ff-11dc-8314-0800200c9a66***"
    rv = []
    for rec_key in sorted(recs):
        rec = recs[rec_key]
        d = OrderedDict(uuid=uuid.uuid4().hex.upper())
        d["updatedAt"] = int(rec.last_modified)
        d["title"] = rec.title
        if rec.url:
            d.setdefault("secureContents", {}).setdefault("URLs", []).append(
            {
                "label": "",
                "url": rec.url,
            })
        if rec.notes:
            d.setdefault("secureContents", {})["notesPlain"] = rec.notes
        if rec.username:
            d.setdefault("secureContents", {}).setdefault("fields", []).append(
            {
                "name": rec.username_type,
                "value": rec.username,
                "type": "T",
                "designation": "username"
            })
        if rec.password:
            d.setdefault("secureContents", {}).setdefault("fields", []).append(
            {
                "name": rec.password_type,
                "value": rec.password,
                "type": "P",
                "designation": "password"
            })
        if rec.category:
            d["openContents"] = {"tags": [rec.category]}
        d["createdAt"] = int(rec.last_modified)
        d["typeName"] = "webforms.WebForm"
        rv.append(json.dumps(d))
        rv.append(sep)
    return "\n".join(rv) + "\n"

def combine_recs(text_recs, html_recs):
    rv = {}
    assert set(text_recs.keys()) == set(html_recs.keys())
    def assert_msg(trec, hrec):
        return "%s\n%s" % (
            json.dumps(trec._asdict(), indent=2),
            json.dumps(hrec, indent=2),
        )
    for key in text_recs:
        trec = text_recs[key]
        hrec = html_recs[key]
        trec = trec._replace(
            last_accessed=hrec.last_accessed,
            last_modified=hrec.last_modified,
        )
        assert hrec.title == trec.title, assert_msg(hrec, trec)
        ufield = trec.username_type
        pfield = trec.password_type
        assert hrec.get(ufield, '') == trec.username, assert_msg(hrec, trec)
        assert hrec.get(pfield, '') == trec.password, assert_msg(hrec, trec)
        assert hrec.get('url', '') == trec.url, assert_msg(hrec, trec)
        rv[key] = trec
    return rv

def usage():
    print __doc__.strip()
    sys.exit(0)

def main():
    if not len(sys.argv) == 3:
        usage()
    text_path = None
    html_path = None
    for arg in sys.argv[1:]:
        if arg.endswith(".html"):
            html_path = arg
        elif arg.endswith(".txt"):
            text_path = arg
    if not all([text_path, html_path]):
        usage()
    blowfish_initialize()
    text_recs = read_text_input(text_path)
    html_recs = read_html_input(html_path)
    recs = combine_recs(text_recs, html_recs)
    with open("data.1pif", "w") as f:
        f.write(to_1pif(recs))
    print "Wrote data.1pif"

if __name__ == '__main__':
    main()
