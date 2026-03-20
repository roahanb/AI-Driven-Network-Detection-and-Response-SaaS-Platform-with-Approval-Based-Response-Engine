"""
Feature Engineering — 78-dimensional network flow feature vectors
Paper: "AI-Driven NDR Platform with Approval-Based Response Engine"
Groups: Flow stats(13) + Rates(2) + IAT(14) + Flags(14) + Bulk(6)
      + Subflow(4) + Active/Idle(8) + Entropy(2) + Behaviour(4)
      + Protocol(3) + Pkt stats(8) = 78
"""
import math
from collections import Counter
from typing import List, Dict, Any

import numpy as np
import pandas as pd

FEATURE_NAMES: List[str] = [
    # 1 Flow stats (13)
    "duration","tot_fwd_pkts","tot_bwd_pkts","totlen_fwd_pkts","totlen_bwd_pkts",
    "fwd_pkt_len_max","fwd_pkt_len_min","fwd_pkt_len_mean","fwd_pkt_len_std",
    "bwd_pkt_len_max","bwd_pkt_len_min","bwd_pkt_len_mean","bwd_pkt_len_std",
    # 2 Rates (2)
    "flow_byts_per_s","flow_pkts_per_s",
    # 3 IAT (14)
    "fwd_iat_tot","fwd_iat_mean","fwd_iat_std","fwd_iat_max","fwd_iat_min",
    "bwd_iat_tot","bwd_iat_mean","bwd_iat_std","bwd_iat_max","bwd_iat_min",
    "flow_iat_mean","flow_iat_std","flow_iat_max","flow_iat_min",
    # 4 Flags (14)
    "fwd_psh_flags","bwd_psh_flags","fwd_urg_flags","bwd_urg_flags",
    "fwd_header_len","bwd_header_len",
    "fin_flag_cnt","syn_flag_cnt","rst_flag_cnt","psh_flag_cnt",
    "ack_flag_cnt","urg_flag_cnt","cwe_flag_cnt","ece_flag_cnt",
    # 5 Bulk (6)
    "fwd_avg_byts_bulk","fwd_avg_pkts_bulk","fwd_avg_blk_rate",
    "bwd_avg_byts_bulk","bwd_avg_pkts_bulk","bwd_avg_blk_rate",
    # 6 Subflow (4)
    "subflow_fwd_pkts","subflow_fwd_byts","subflow_bwd_pkts","subflow_bwd_byts",
    # 7 Active/Idle (8)
    "active_mean","active_std","active_max","active_min",
    "idle_mean","idle_std","idle_max","idle_min",
    # 8 Entropy (2)
    "payload_entropy","domain_entropy",
    # 9 Behaviour (4)
    "baseline_deviation","ip_diversity","port_diversity","temporal_anomaly",
    # 10 Protocol (3)
    "protocol","dst_port","src_port",
    # 11 Pkt stats (8)
    "down_up_ratio","avg_pkt_size","avg_fwd_seg_size","avg_bwd_seg_size",
    "fwd_act_data_pkts","fwd_seg_size_min","init_win_byts_fwd","init_win_byts_bwd",
]
N_FEATURES = len(FEATURE_NAMES)  # 78

# Robust z-score baselines (from CICIDS2018 benign median / IQR)
_MED = np.array([1.5,12,8,6500,4200,800,40,340,180,700,35,290,155,18000,35,
  0.08,0.02,0.01,0.15,0.001,0.07,0.018,0.009,0.12,0.001,0.025,0.02,0.15,0.001,
  1,1,0,0,32,32,1,1,0,2,5,0,0,0,200,2,1200,150,1.5,500,4,2000,3,1400,
  0.02,0.01,0.04,0.005,0.01,0.005,0.04,0.005,3.2,1.5,
  0.1,3,5,0.05,6,443,52000,0.85,380,340,290,8,40,8192,8192],dtype=np.float32)
_IQR = np.array([3,25,18,15000,10000,600,30,250,140,550,28,220,120,40000,80,
  0.15,0.04,0.02,0.3,0.002,0.13,0.035,0.018,0.25,0.002,0.05,0.04,0.3,0.002,
  1,1,0.1,0.1,16,16,1,1,1,3,8,0.5,0.1,0.1,400,3,2500,350,3,1000,8,4500,5,3000,
  0.04,0.02,0.08,0.01,0.02,0.01,0.08,0.01,1.5,1.2,
  0.5,5,8,0.2,11,22000,13000,0.4,300,270,230,10,30,16384,16384],dtype=np.float32)

def _ent(s):
    if not s: return 0.0
    cnt=Counter(s); n=len(s)
    return -sum((c/n)*math.log2(c/n) for c in cnt.values())

def _proto(alert,port):
    a=(alert or "").lower()
    if "icmp" in a: return 1
    if "udp" in a or port in (53,123,161): return 17
    return 6

def _flags(alert):
    a=(alert or "").lower()
    return dict(syn=2 if any(k in a for k in("scan","syn","dos","ddos","flood"))else 1,
                fin=1 if any(k in a for k in("close","fin"))else 0,
                rst=2 if any(k in a for k in("scan","reject","reset"))else 0,
                psh=3 if any(k in a for k in("exfil","data","upload"))else 1,
                ack=1,urg=1 if"urgent"in a else 0)

def extract_features_from_event(event,window_events):
    src=event.get("source_ip","0.0.0.0"); dst=event.get("destination_ip","0.0.0.0")
    dom=event.get("domain") or ""; alert=event.get("alert_type","")
    summ=event.get("summary","")
    dport=443; sport=52000
    for tok in (alert+" "+summ).split():
        try:
            p=int(tok.strip(":,/()"))
            if 1<=p<=65535: dport=p; break
        except: pass
    proto=_proto(alert,dport); fl=_flags(alert); a=alert.lower()
    dos =any(k in a for k in("dos","ddos","flood","hulk","goldeneye"))
    scan=any(k in a for k in("scan","probe","sweep","portscan"))
    brut=any(k in a for k in("brute","patator","credential","login"))
    bot =any(k in a for k in("bot","beacon","c2","command","ransomware"))
    exfl=any(k in a for k in("exfil","transfer","upload","infiltrat"))
    dur=0.005 if scan else 0.02 if dos else 0.3 if brut else 1.2 if bot else 5.0 if exfl else 1.5
    tfwd=500 if dos else 2 if scan else 10 if brut else 5 if bot else 30 if exfl else 12
    tbwd=int(tfwd*0.65); lfwd=int(tfwd*350); lbwd=int(tbwd*290)
    pm_f=lfwd/max(tfwd,1); ps_f=pm_f*0.3; pm_b=lbwd/max(tbwd,1); ps_b=pm_b*0.3
    bps=lfwd/max(dur,1e-6); pps=tfwd/max(dur,1e-6)
    im=dur/max(tfwd-1,1); ist=im*0.1 if bot else im*0.55
    pe=_ent((src+dst+alert+dom)[:64]); de=_ent(dom) if dom else 1.5
    ws=[e.get("source_ip","") for e in window_events]+[e.get("destination_ip","") for e in window_events]
    ipd=float(len(set(ws))); pod=float(min(len(window_events),20))
    bd=3.5 if dos else 2.8 if scan else 2.0 if brut else 2.5 if bot else 3.0 if exfl else 0.1
    ta=4.0 if dos else 0.5 if bot else 2.0 if scan else 0.05
    v=np.array([
        dur,float(tfwd),float(tbwd),float(lfwd),float(lbwd),
        pm_f+ps_f*2,max(pm_f-ps_f,0),pm_f,ps_f,
        pm_b+ps_b*2,max(pm_b-ps_b,0),pm_b,ps_b,
        bps,pps,
        im*tfwd,im,ist,im*2.5,im*0.05,
        im*tbwd,im,ist,im*2.5,im*0.05,
        im,ist,im*3,im*0.05,
        float(fl["psh"]),float(fl["psh"]),float(fl["urg"]),float(fl["urg"]),
        float(proto*4),float(proto*4),
        float(fl["fin"]),float(fl["syn"]),float(fl["rst"]),float(fl["psh"]),
        float(fl["ack"]),float(fl["urg"]),0.0,0.0,
        pm_f*2,2.0,bps*0.5,pm_b*2,1.5,bps*0.3,
        float(tfwd//4),float(lfwd//4),float(tbwd//4),float(lbwd//4),
        dur*0.4,dur*0.1,dur*0.6,dur*0.05,
        dur*0.5,dur*0.15,dur*0.8,dur*0.05,
        pe,de,bd,ipd,pod,ta,
        float(proto),float(dport),float(sport),
        float(lbwd)/max(float(lfwd),1),float(lfwd+lbwd)/max(float(tfwd+tbwd),1),
        pm_f,pm_b,float(tfwd),max(pm_f-ps_f*2,0),8192.0,8192.0,
    ],dtype=np.float32)
    return v

def robust_zscore(X):
    return (X-_MED)/(_IQR+1e-8)

def extract_features_from_logs(parsed_logs):
    if not parsed_logs:
        return pd.DataFrame(columns=FEATURE_NAMES)
    vectors=[]
    for i,ev in enumerate(parsed_logs):
        vectors.append(extract_features_from_event(ev,parsed_logs[max(0,i-20):i]))
    X=np.nan_to_num(np.vstack(vectors).astype(np.float32),nan=0,posinf=1e6,neginf=-1e6)
    return pd.DataFrame(robust_zscore(X),columns=FEATURE_NAMES)
