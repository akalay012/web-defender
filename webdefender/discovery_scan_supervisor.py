"""Independent wall-clock supervisor for one discovery analyzer process group."""
import os, signal, sys, time

def main():
    if len(sys.argv)!=4: raise SystemExit(2)
    pgid=int(sys.argv[1]); timeout=max(10,min(300,int(sys.argv[2]))); done=sys.argv[3]
    print(f"[DISCOVERY-SUPERVISOR] armed | pgid={pgid} | timeout={timeout}s",flush=True)
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if os.path.exists(done):
            print(f"[DISCOVERY-SUPERVISOR] disarmed | pgid={pgid} | completed=true",flush=True)
            return
        time.sleep(1)
    if os.path.exists(done): return
    print(f"[DISCOVERY-SUPERVISOR] deadline reached | pgid={pgid} | action=SIGKILL",flush=True)
    try: os.killpg(pgid,signal.SIGKILL)
    except ProcessLookupError: pass
    except Exception as exc:
        print(f"[DISCOVERY-SUPERVISOR][ERROR] kill failed | pgid={pgid} | {type(exc).__name__}: {exc}",flush=True)

if __name__=="__main__": main()
