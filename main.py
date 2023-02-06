import sklearn as sk
import pandas as pd
from matplotlib import pyplot as plt
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
                                                                       test_size=0.30,
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

# The following code is partly taken from the sklearn documentation and modified to our needs
# https://scikit-learn.org/stable/auto_examples/tree/plot_unveil_tree_structure.html#sphx-glr-auto-examples-tree-plot-unveil-tree-structure-py

node_indicator = rfc.estimators_[0].decision_path(X_test)
leaf_id = rfc.apply(X_test)

available_features = rfc.estimators_[0].tree_.feature
threshold = rfc.estimators_[0].tree_.threshold
children_left = rfc.estimators_[0].tree_.children_left
children_right = rfc.estimators_[0].tree_.children_right

# print(node_indicator)

# Be aware, removing this may break the code
X_test = X_test.reset_index()

list_of_rules = []

for sample_id in X_test.index:
    current_rule_set = []
    new_rule = {}

    # obtain ids of the nodes `sample_id` goes through, i.e., row `sample_id`
    node_index = node_indicator.indices[
                 node_indicator.indptr[sample_id]: node_indicator.indptr[sample_id + 1]
                 ]

    print("Rules used to predict sample {id}:\n".format(id=sample_id))
    for node_id in node_index:
        # continue to the next node if it is a leaf node
        if leaf_id[sample_id] == node_id:
            continue

        # print("DEBUG" + str(sample_id))
        # print("DEBUG" + str(node_id))
        # print("DEBUG" + str(feature))
        # print(train_db.columns)
        # print("DEBUG TYPE" + str(type(feature)))
        # print("DEBUG SIZE" + str(X_test.shape))

        greater = None
        threshold_value = threshold[node_id]
        feature = X_test.columns[available_features[node_id]]

        # check if value of the split feature for sample 0 is below threshold
        if X_test.loc[sample_id][X_test.columns[available_features[node_id]]] <= threshold[node_id]:
            threshold_sign = "<="
            greater = False
        else:
            threshold_sign = ">"
            greater = True

        print(
            "decision node {node} : (X_test[{sample}, {feature}] = {value}) "
            "{inequality} {threshold})".format(
                node=node_id,
                sample=sample_id,
                feature=train_db.columns[available_features[node_id]],
                value=X_test.loc[sample_id][train_db.columns[available_features[node_id]]],
                inequality=threshold_sign,
                threshold=threshold_value,
            )
        )

        new_rule = {
            "greater": greater,
            "threshold": threshold_value,
            "feature": feature
        }

        current_rule_set.append(new_rule)

        print("ID " + str(node_id))
        print("last " + str(node_index[-1]))

        if node_id == node_index[-2]:
            if current_rule_set not in list_of_rules:
                list_of_rules.append(current_rule_set)
            print("Clearing ruleset")
            current_rule_set = {}

print(list_of_rules)

#TODO Save to scv for further use in the next script to create plots

# for data_point in y_test.rows:
# This may need to be expanded to multiple trees in the future
#    tree = rfc.estimators_
#    tree.decision_path(data_point)

# for i, tree in enumerate(rfc.estimators_):
#    tree_struct = tree.tree_
#    print(tree_struct.children_left[0])
#    print(tree_struct.children_right[0])
#    print(type(tree))

#fig, axes = plt.subplots(nrows=1, ncols=1, figsize=(4, 4), dpi=800)
#sk.tree.plot_tree(rfc.estimators_[0],
#                  node_ids=True,
#                  feature_names=train_db.columns,
#                  filled=True)
#fig.savefig("rf_individualtree_debug" + str(1337) + ".png")
