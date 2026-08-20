import numpy as np
import pandas as pd

TIME_BUCKETS = [
    'night',
    'early_morning',
    'morning',
    'afternoon',
    'evening',
    'late_night'
]

DIRECTION = [
    'inbound','outbound','lan_local'
]

def log_transform(df, cols):
    df = df.copy()

    for c in cols:
        if c in df.columns:
            df[c] = np.log1p(df[c].clip(lower=0))
            #log(1+x) is used to avoid log(0) which is undefined and also to avoid negative values in the log transformation

    return df

#not using get_dummies here because they create colmn only if that feature is present in json but here it might be such that data was not captured in night or somehting so we need to know the data is not present in that time bucket so we need to create a column for that time bucket and fill it with 0s so manual way
def one_hot_bucket(df):
    df = df.copy()

    if 'time_bucket' in df.columns:
        for bucket in TIME_BUCKETS:
            df[f'bucket_{bucket}'] = (df['time_bucket'] == bucket).astype(int)
        #this above line returns all the rows as true or false based if time_bucket of that row is b or not and that true or false is converted to 1 and 0 
        #so each row has bucket_morning bucket_afternoon ... and 0 means false 1 means true
        df = df.drop(columns=['time_bucket'])

    return df

def preprocess_windows(df):
    w=one_hot_bucket(df)
    # log-transform the skewed byte/rate/duration columns
    skew_cols = ['total_bytes', 'total_duration_s', 'fwd_packets', 'bwd_packets', 'ack_count', 'psh_count', 'avg_fwd_pkt_size', 'avg_bwd_pkt_size']
    drop_cols=['timestamp', 'window_size_s']
    w = log_transform(w, skew_cols)
    w_features=[c for c in w.columns if c not in drop_cols]

    return w,w_features

def preprocess_flows(df):
    fl=one_hot_bucket(df)
    skew_cols = ['flow_duration_s', 'fwd_bytes', 'bwd_bytes',
             'flow_packets_per_s', 'flow_bytes_per_s',
             'fwd_bytes_per_s', 'bwd_bytes_per_s',
             'fwd_packets_per_s', 'bwd_packets_per_s']
    fl = log_transform(fl, skew_cols)
    # drop identifiers / non-numeric columns not meant as features
    # encode remaining categoricals
    # we cannot give string to the IF so pd.get_dummies takes a categorical column example DIRECTIONS here and creates a seperate   0/1 column for each unique value => inbound outbound

    #   direction_inbound   direction_outbound
    #0                   0                  1     this is outbound
    #1                   1                  0     this is inbound
    #2                   0                  0

    for dir in DIRECTION:
        fl[f'direction_{dir}']=(fl['direction']==dir).astype(int)
    fl=fl.drop(columns=['direction'])

    for bool_col in ['internal_src', 'internal_dst']:
        if bool_col in fl.columns:
            fl[bool_col] = fl[bool_col].astype(int)

    
    drop_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
    fl_features=[c for c in fl.columns if c not in drop_cols]

    return fl,fl_features

def preprocess_ip_windows(df):
    ipw=one_hot_bucket(df)
    skew_cols = ['total_bytes', 'total_duration_s']
    ipw = log_transform(ipw, skew_cols)
    # IP itself is deliberately excluded as a feature (not a stable identity across networks/DHCP)
    drop_cols = ['ip', 'window_start']
    ipw_features = [c for c in ipw.columns if c not in drop_cols]
    return ipw,ipw_features
