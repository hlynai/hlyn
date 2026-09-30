# SPDX-License-Identifier: Apache-2.0
"""Which Mach services does each client need?

Each client runs under hlyn's own macOS profile with the blanket
`(allow mach-lookup)` replaced by an allowlist that starts empty. The
policy grants everything else the client could want (read everywhere, its
own scratch folders, any program, the network ports it uses), so a failure
is a missing service. The allowlist grows from the Environment's denials until
the client succeeds, then is minimised: each service is dropped in turn and
kept only if the client then fails.

    python3 tools/hostlab/machlab.py            every client
    python3 tools/hostlab/machlab.py curl git   just these

Prints one JSON object per client and writes them all to machlab.json in a
scratch folder (printed at the end). Clients that aren't installed are
skipped. Some leave state behind for the length of the run only: a test
keychain in the scratch folder, a Calculator window it opened hidden and
then quits (only if it wasn't already running).
"""
import json, os, re, shutil, subprocess, sys, tempfile, time, uuid
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from hlyn.core import mac
from hlyn.policy import Policy

LAB = os.path.dirname(os.path.abspath(__file__))  # fetch (swiftc -O fetch.swift -o fetch), leaf.pem (certs.sh)
HOME = os.path.expanduser("~")
WORK = os.path.realpath(tempfile.mkdtemp(prefix="machlab-"))
TMP = os.path.realpath(tempfile.gettempdir())
# The per-user cache folder (/var/folders/../C), where clang and swift keep their module caches.
CACHE = os.path.realpath(subprocess.run(["/usr/bin/getconf", "DARWIN_USER_CACHE_DIR"], capture_output=True,
                                        text=True).stdout.strip() or TMP)
KEYCHAIN = os.path.join(WORK, "machlab.keychain-db")
SECRET = "s3cret-machlab"


def policy(net=(443,), write=()):
    return Policy(read=True, write=(WORK, TMP, CACHE, "/private/tmp", "/dev", *write), exec=True, net=net, env=True)


def which(name):
    return shutil.which(name, path="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")


def keychain():
    """A keychain of our own, unlocked, holding one password: never the user's."""
    if not os.path.exists(KEYCHAIN):
        subprocess.run(["/usr/bin/security", "create-keychain", "-p", "machlab", KEYCHAIN], check=True)
        subprocess.run(["/usr/bin/security", "add-generic-password", "-a", "machlab", "-s", "hlyn-machlab",
                        "-w", SECRET, KEYCHAIN], check=True)
    subprocess.run(["/usr/bin/security", "unlock-keychain", "-p", "machlab", KEYCHAIN], check=True)


def calculator_running():
    return subprocess.run(["/usr/bin/pgrep", "-x", "Calculator"], capture_output=True).returncode == 0


def write(path, text):
    with open(path, "w") as fh:
        fh.write(text)
    return path


# name: (argv, policy, check(returncode, output) -> bool, setup or None, stdin or None)
def clients():
    git = which("git")
    node = which("node")
    out = {
        "curl": ([which("curl"), "-sS", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com"],
                 policy(), lambda rc, text: rc == 0 and text.strip().endswith("200"), None, None),
        "python urllib": ([sys.executable, "-c",
                           "import urllib.request as u; print(u.urlopen('https://example.com').status)"],
                          policy(), lambda rc, text: rc == 0 and "200" in text, None, None),
        "node fetch": ([node, "-e", "fetch('https://example.com').then(r=>console.log(r.status))"
                        ".catch(e=>{console.log(e.cause||e);process.exit(1)})"],
                       policy(), lambda rc, text: rc == 0 and "200" in text, None, None),
        "git ls-remote": ([git, "ls-remote", "https://github.com/git/git", "HEAD"],
                          policy(), lambda rc, text: rc == 0 and "HEAD" in text, None, None),
        "keychain (security find-generic-password)": (
            ["/usr/bin/security", "find-generic-password", "-s", "hlyn-machlab", "-w", KEYCHAIN],
            policy(net=False), lambda rc, text: rc == 0 and SECRET in text, keychain, None),
        "git credential-osxkeychain get": (
            [git, "credential-osxkeychain", "get"], policy(net=False),
            lambda rc, text: rc == 0 and "error" not in text.lower(), None,
            "protocol=https\nhost=hlyn-machlab.invalid\n\n"),
        "open (an app, hidden)": (
            ["/usr/bin/open", "-g", "-j", "-a", "Calculator"], policy(net=False),
            lambda rc, text: rc == 0, None, None),
        "xcrun --find clang": (["/usr/bin/xcrun", "--find", "clang"], policy(net=False),
                               lambda rc, text: rc == 0 and "clang" in text, None, None),
        "clang (compile and link C)": (
            ["/usr/bin/clang", write(os.path.join(WORK, "hello.c"), "int main(void){return 0;}\n"),
             "-o", os.path.join(WORK, "hello-c")], policy(net=False),
            lambda rc, text: rc == 0, None, None),
        "swiftc (compile Swift)": (
            ["/usr/bin/swiftc", write(os.path.join(WORK, "hello.swift"), 'print("hello")\n'),
             "-o", os.path.join(WORK, "hello-swift")], policy(net=False, write=(os.path.join(HOME, "Library/Caches"), os.path.join(HOME, "Library/Developer"))),
            lambda rc, text: rc == 0, None, None),
        "swift (run a script)": (
            ["/usr/bin/swift", os.path.join(WORK, "hello.swift")],
            policy(net=False, write=(os.path.join(HOME, "Library/Caches"), os.path.join(HOME, "Library/Developer"))),
            lambda rc, text: rc == 0 and "hello" in text, None, None),
        "xcodebuild -version": (["/usr/bin/xcodebuild", "-version"], policy(net=False),
                                lambda rc, text: rc == 0, None, None),
    }
    if os.path.exists(os.path.join(LAB, "fetch")):
        out["swift URLSession (fetch)"] = (
            [os.path.join(LAB, "fetch"), "https://example.com"], policy(write=(os.path.join(HOME, "Library/Caches/fetch"),)),
            lambda rc, text: rc == 0, None, None)
    java = os.environ.get("MACHLAB_JAVA")
    if java:
        out["java (HttpClient)"] = (
            [java, write(os.path.join(WORK, "Get.java"),
                         "public class Get { public static void main(String[] a) throws Exception {"
                         " var c = java.net.http.HttpClient.newHttpClient();"
                         " var r = c.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(\"https://example.com\")).build(),"
                         " java.net.http.HttpResponse.BodyHandlers.discarding());"
                         " System.out.println(r.statusCode()); } }\n")],
            policy(), lambda rc, text: rc == 0 and "200" in text, None, None)
    electron = os.environ.get("MACHLAB_ELECTRON")
    if electron:
        main = write(os.path.join(WORK, "main.js"),
                     "const {app} = require('electron');"
                     "app.whenReady().then(async () => { const r = await fetch('https://example.com');"
                     " console.log('status', r.status); app.quit(); });\n")
        out["electron (an app that fetches and quits)"] = (
            [electron, main], policy(write=(os.path.join(HOME, "Library/Application Support"),
                                            os.path.join(HOME, "Library/Caches"))),
            lambda rc, text: rc == 0 and "status 200" in text, None, None)
    return {name: spec for name, spec in out.items() if spec[0][0]}


def run(argv, grants, allow, stdin):
    tag = "machlab-" + uuid.uuid4().hex[:8]
    text = mac.profile(grants, tag)
    rules = "".join(f' (global-name "{name}")' for name in sorted(allow))
    assert "(allow mach-lookup)" in text
    text = text.replace("(allow mach-lookup)", f"(allow mach-lookup{rules})" if allow else "")
    start = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        done = subprocess.run(["/usr/bin/sandbox-exec", "-p", text, *argv], capture_output=True, text=True,
                              timeout=120, input=stdin, env={**os.environ, "HOME": HOME}, cwd=WORK)
        rc, output = done.returncode, done.stdout + done.stderr
    except subprocess.TimeoutExpired as exc:
        rc, output = -1, f"timed out: {exc.stdout or ''}{exc.stderr or ''}"
    time.sleep(1.5)
    log = subprocess.run(["/usr/bin/log", "show", "--style", "compact", "--start", start, "--predicate",
                          f'sender == "Sandbox" AND eventMessage CONTAINS "{tag}"'],
                         capture_output=True, text=True).stdout
    denied = set(re.findall(r"deny\(\d+\) mach-lookup (\S+)", log))
    return rc, output, denied


def measure(name, spec):
    argv, grants, check, setup, stdin = spec
    if setup:
        setup()
    allow, rounds = set(), []
    for number in range(15):
        rc, output, denied = run(argv, grants, allow, stdin)
        ok = check(rc, output)
        rounds.append({"round": number, "ok": ok, "rc": rc, "tail": output.strip().splitlines()[-2:],
                       "denied": sorted(denied)})
        new = denied - allow
        if ok or not new:
            break
        allow |= new
    need = set(allow)
    if ok:
        for service in sorted(allow):
            rc, output, _ = run(argv, grants, need - {service}, stdin)
            if check(rc, output):
                need.discard(service)
    # And the same client with the blanket grant, as hlyn ships today.
    tag = "machlab-" + uuid.uuid4().hex[:8]
    done = subprocess.run(["/usr/bin/sandbox-exec", "-p", mac.profile(grants, tag), *argv], capture_output=True,
                          text=True, timeout=120, input=stdin, env={**os.environ, "HOME": HOME}, cwd=WORK)
    return {"works with no service": rounds[0]["ok"], "works in the end": ok, "needed": sorted(need),
            "denied in the first round": rounds[0]["denied"], "rounds": len(rounds),
            "last output": rounds[-1]["tail"],
            "under today's blanket grant": check(done.returncode, done.stdout + done.stderr)}


def searched():
    done = subprocess.run(["/usr/bin/security", "list-keychains", "-d", "user"], capture_output=True, text=True)
    return [line.strip().strip('"') for line in done.stdout.splitlines() if line.strip()]


def main():
    known = clients()
    names = sys.argv[1:] or list(known)
    was_running = calculator_running()
    search = searched()  # create-keychain adds ours to the user's list; put it back as it was
    results = {}
    try:
        for name in names:
            if name not in known:
                print(f"{name}: not installed or unknown; skipped", flush=True)
                continue
            results[name] = measure(name, known[name])
            print(json.dumps({name: results[name]}, indent=1), flush=True)
    finally:
        if not was_running and calculator_running():
            subprocess.run(["/usr/bin/osascript", "-e", 'quit app "Calculator"'], capture_output=True)
        if os.path.exists(KEYCHAIN):
            subprocess.run(["/usr/bin/security", "delete-keychain", KEYCHAIN], capture_output=True)
        if searched() != search:
            subprocess.run(["/usr/bin/security", "list-keychains", "-d", "user", "-s", *search], check=True)
        print("keychain search list restored:", searched() == search)
    path = os.path.join(WORK, "machlab.json")
    with open(path, "w") as fh:
        json.dump(results, fh, indent=1)
    print("written:", path)


main()
