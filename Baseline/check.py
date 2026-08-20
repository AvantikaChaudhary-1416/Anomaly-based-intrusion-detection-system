import pandas as pd
import json
from sklearn.ensemble import IsolationForest

TIME_BUCKETS = ['night', 'early_morning', 'morning', 'afternoon', 'evening', 'late_night']

def one_hot_bucket(df):
    if 'time_bucket' in df.columns:
        for b in TIME_BUCKETS:
            df[f'bucket_{b}'] = (df['time_bucket'] == b).astype(int)
            #this above line returns all the rows as true or false based if time_bucket of that row is b or not and that true or false is converted to 1 and 0 
            #so each row has bucket_morning bucket_afternoon ... and 0 means false 1 means true
        df = df.drop(columns=['time_bucket'])
    return df

def train_model(df,features,name):
    X=df[features].fillna(0)
    model = IsolationForest(
            n_estimators=200,
            contamination="auto",
            random_state=42,
            n_jobs=-1,
        )
    model.fit(X)

    scores=model.decision_function(X)
    preds=model.predict(X)
    df["anomaly_score"]=scores
    df["anomaly_flag"]=preds

    flagged=df[df["anomaly_flag"]==-1].sort_values("anomaly_score")
    print(f"Flagged:{len(flagged)} rows")
    feature_check = ['flow_duration_s', 'fwd_bytes', 'bwd_bytes', 'fwd_packets', 'bwd_packets','flow_packets_per_s','flow_bytes_per_s']
    print(flagged[feature_check + ['anomaly_score']].head(20))



with open("flows.json") as f:
    fl=pd.DataFrame(json.load(f))

'''print(fl.shape)

fl=one_hot_bucket(fl)
drop_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
fl_features = [c for c in fl.columns if c not in drop_cols]
for cat_col in ['direction']:
    if cat_col in fl.columns:
        dummies = pd.get_dummies(fl[cat_col], prefix=cat_col)  #this is a function that cretes the column with 0/1
        fl = pd.concat([fl, dummies], axis=1)     #concatenate the new columns produced by pd.dummies as columns(axis=1)
        fl_features = [c for c in fl_features if c != cat_col] + list(dummies.columns)   #drop directions

for bool_col in ['internal_src', 'internal_dst']:
    if bool_col in fl.columns:
        fl[bool_col] = fl[bool_col].astype(int)



train_model(fl, fl_features, "flows_model")
'''

with open("windows.json") as f:
    w=pd.DataFrame(json.load(f))
print(w.shape)

with open("ip_windows.json") as f:
    ip=pd.DataFrame(json.load(f))
print(ip.shape)

print(fl.columns)
print(ip.columns)
print(w.columns)
