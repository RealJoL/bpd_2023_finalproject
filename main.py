import sklearn as sk
import pandas as pd
from numpy import dtype
from pandas.core.dtypes.common import is_numeric_dtype
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# Maybe extend to further data sets
db = pd.read_csv("capture20110818-2.binetflow")

db['Label'].unique()
malicious = list(filter(lambda x: "Botnet" in x, db['Label'].unique()))

all_bad_db = db[db["Label"].isin(malicious)]
all_good_db = db[~ db["Label"].isin(malicious)]

# Set binary label for db

all_good_db = all_good_db.assign(final_label=0)
all_bad_db = all_bad_db.assign(final_label=1)

# Remove too specific field like IP addresses

columns_to_drop = ["SrcAddr", "DstAddr", "StartTime"]

all_good_db = all_good_db.drop(columns=columns_to_drop)
all_bad_db = all_bad_db.drop(columns=columns_to_drop)

pre_proc_db = pd.concat([all_good_db, all_bad_db], ignore_index=True, verify_integrity=True)

# Encode labels to numeric
label_encs = {}

for col in pre_proc_db:
    le = LabelEncoder()
    le.fit(pre_proc_db[col].unique())
    label_encs[col] = le

train_db = pd.DataFrame(pre_proc_db)
for col in pre_proc_db:
    if not is_numeric_dtype(pre_proc_db[col]):
        train_db[col] = label_encs[col].transform(pre_proc_db[col])
    else:
        train_db[col] = pre_proc_db[col].fillna(0)

X_train, X_test, y_train, y_test = sk.model_selection.train_test_split(pre_proc_db.drop(columns=['final_label']),
                                                                       pre_proc_db['final_label'],
                                                                       test_size=0.20,
                                                                       random_state=42)

rfc = RandomForestClassifier(n_estimators=100,
                             max_depth=10,
                             bootstrap=True,
                             random_state=42,
                             verbose=1,
                             class_weight='balanced')

rfc.fit(X_train, y_train)

val_y = rfc.predict(X_test)

print("Scoring: " + str(sk.metrics.mean_squared_error(val_y, y_test)))
