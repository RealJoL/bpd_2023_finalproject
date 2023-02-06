import sklearn as sk
import pandas as pd
from pandas.core.dtypes.common import is_numeric_dtype
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# TODO Maybe extend to further data sets
db = pd.read_csv("capture20110818-2.binetflow")

db['Label'].unique()
malicious = list(filter(lambda x: "Botnet" in x, db['Label'].unique()))

all_bad_db = db[db["Label"].isin(malicious)]
all_good_db = db[~ db["Label"].isin(malicious)]

# Set binary label for db

all_good_db = all_good_db.assign(final_label=0)
all_bad_db = all_bad_db.assign(final_label=1)

# Remove too specific field like IP addresses

columns_to_drop = ["SrcAddr", "DstAddr", "StartTime", "Label"]

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

rfc = RandomForestClassifier(n_estimators=1,
                             max_depth=4,
                             bootstrap=True,
                             random_state=42,
                             verbose=1,
                             class_weight='balanced')

rfc.fit(X_train, y_train)

val_y = rfc.predict(X_test)

print("Scoring: " + str(sk.metrics.mean_squared_error(val_y, y_test)))

print(rfc.feature_importances_)

rules = []

#for i, tree in enumerate(rfc.estimators_):
#    tree_struct = tree.tree_
#    print(tree_struct.children_left[0])
#    print(tree_struct.children_right[0])
#    print(type(tree))
    #fig, axes = plt.subplots(nrows=1, ncols=1, figsize=(4, 4), dpi=800)
    #sk.tree.plot_tree(tree,
    #               feature_names=train_db.columns,
    #               filled=True)
    #fig.savefig("rf_individualtree"+ str(i) + ".png")


# The following code is partly taken from the sklearn documentation and modified to our needs

node_indicator = rfc.estimators_[0].decision_path(X_test)
leaf_id = rfc.apply(X_test)

feature = rfc.estimators_[0].tree_.feature
threshold = rfc.estimators_[0].tree_.threshold

#print(node_indicator)

sample_id = 0
# obtain ids of the nodes `sample_id` goes through, i.e., row `sample_id`
node_index = node_indicator.indices[
    node_indicator.indptr[sample_id] : node_indicator.indptr[sample_id + 1]
]

print("Rules used to predict sample {id}:\n".format(id=sample_id))
for node_id in node_index:
    # continue to the next node if it is a leaf node
    if leaf_id[sample_id] == node_id:
        continue

    # check if value of the split feature for sample 0 is below threshold
    if X_test[sample_id, feature[node_id]] <= threshold[node_id]:
        threshold_sign = "<="
    else:
        threshold_sign = ">"

    print(
        "decision node {node} : (X_test[{sample}, {feature}] = {value}) "
        "{inequality} {threshold})".format(
            node=node_id,
            sample=sample_id,
            feature=feature[node_id],
            value=X_test[sample_id, feature[node_id]],
            inequality=threshold_sign,
            threshold=threshold[node_id],
        )
    )


#for data_point in y_test.rows:
    # This may need to be expanded to multiple trees in the future
#    tree = rfc.estimators_
#    tree.decision_path(data_point)