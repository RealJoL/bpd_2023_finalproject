import json
from datetime import datetime
import sklearn as sk
import pandas as pd
from pandas.core.dtypes.common import is_numeric_dtype
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

'''This script, much like main.py will train a model with the specific encoding 
and will return a rule set. Here, the difference lies in multiple estimators being used in an ensemble 
method.

If you want to modify input or output, you must change paths accordingly, but running this script alone 
will create a timestamped output with the CTU-13 data set used by us.

Warning: On some versions of sklearn, the index column may need to be removed additionally.'''

# This data is generating our ruleset and gives an encoding in case String data fields are used.
# String data set may not be the best option, as discussed in our paper.

# Reading df

db = pd.read_csv("../capture20110818-2.binetflow")

# Parametrizable output
output_file = "../output/rulenc/nostring/"
columns_to_drop = ["SrcAddr", "DstAddr", "StartTime", "Label", "Dir", "Proto"]

# Here we filter by label, separating our data set to give it labels
db['Label'].unique()
malicious = list(filter(lambda x: "Botnet" in x, db['Label'].unique()))

# Set binary label for db

all_bad_db = db[db["Label"].isin(malicious)]
all_good_db = db[~ db["Label"].isin(malicious)]

# Set binary label for db

all_good_db = all_good_db.assign(final_label=0)
all_bad_db = all_bad_db.assign(final_label=1)

all_good_db = all_good_db.drop(columns=columns_to_drop)
all_bad_db = all_bad_db.drop(columns=columns_to_drop)

pre_proc_db = pd.concat([all_good_db, all_bad_db], ignore_index=True, verify_integrity=True)

# Fill Sport and Dport for null to 0 and convert to int
pre_proc_db[['Sport', 'Dport']] = pre_proc_db[['Sport', 'Dport']].fillna(value="0")
pre_proc_db['Sport'] = pre_proc_db['Sport'].apply(lambda x: int(int(x, 16)))
pre_proc_db['Dport'] = pre_proc_db['Dport'].apply(lambda x: int(int(x, 16)))

pre_proc_db[['State']] = pre_proc_db[['State']].fillna(value="NULL")

# Encode labels to numeric values if string fields are present
label_encs = {}
le_encodings = {}
for col in pre_proc_db:
    le = LabelEncoder()
    if not is_numeric_dtype(pre_proc_db[col]):
        le.fit(pre_proc_db[col].unique())
        le_dict = {}
        for item in pre_proc_db[col].unique():
            print(item)
            transformed_item = le.transform([item])
            le_dict[int(transformed_item[0])] = item
        le_encodings[col] = le_dict
        label_encs[col] = le

# Fill empty fields with 0
train_db = pd.DataFrame(pre_proc_db)
for col in pre_proc_db:
    if not is_numeric_dtype(pre_proc_db[col]):
        train_db[col] = label_encs[col].transform(pre_proc_db[col])
    else:
        train_db[col] = pre_proc_db[col].fillna(0)

# Split data into test and train
X_train, X_test, y_train, y_test = sk.model_selection.train_test_split(pre_proc_db.drop(columns=['final_label']),
                                                                       pre_proc_db['final_label'],
                                                                       test_size=0.30,
                                                                       random_state=42)

# Parametrize model
rfc = RandomForestClassifier(n_estimators=3,
                             max_depth=4,
                             bootstrap=True,
                             random_state=42,
                             verbose=1,
                             class_weight='balanced')

# Fit model to data
rfc.fit(X_train, y_train)

# Predict test data
val_y = rfc.predict(X_test)

print("Scoring: " + str(sk.metrics.mean_squared_error(val_y, y_test)))

print(rfc.feature_importances_)

# The following code is partly taken from the sklearn documentation and strongly modified to fit our needs
# https://scikit-learn.org/stable/auto_examples/tree/plot_unveil_tree_structure.html#sphx-glr-auto-examples-tree-plot-unveil-tree-structure-py

# List of rules later converted to df
list_of_rules = []

print("ESTIMATORS " + str(rfc.estimators_))

for i, estimator in enumerate(rfc.estimators_):
    node_indicator = estimator.decision_path(X_test)
    leaf_ids = rfc.apply(X_test)
    print(leaf_ids)

    # Going through the estimators tree features
    available_features = estimator.tree_.feature
    threshold = estimator.tree_.threshold
    children_left = estimator.tree_.children_left
    children_right = estimator.tree_.children_right

    # Be aware, removing this may break the code
    X_test_post = X_test.reset_index()

    # Traversing the tree using the samples from the data set
    for j, sample_id in enumerate(X_test_post.index):
        leaf_id = leaf_ids[j, i]
        current_rule_set = []
        new_rule = {}

        # obtain ids of the nodes `sample_id` goes through, i.e., row `sample_id`
        node_index = node_indicator.indices[
                     node_indicator.indptr[sample_id]: node_indicator.indptr[sample_id + 1]
                     ]

        # print("\nRules used to predict sample {id}:".format(id=sample_id))
        for node_id in node_index:
            # continue to the next node if it is a leaf node
            if leaf_id == node_id:
                continue

            greater = None
            threshold_value = threshold[node_id]
            feature = X_test_post.columns[available_features[node_id]]

            # check if value of the split feature for sample 0 is below threshold
            if X_test_post.loc[sample_id][X_test_post.columns[available_features[node_id]]] <= threshold[node_id]:
                threshold_sign = "<="
                greater = False
            else:
                threshold_sign = ">"
                greater = True

            # New rule set
            new_rule = {
                "greater": greater,
                "threshold": threshold_value,
                "feature": feature
            }

            current_rule_set.append(new_rule)

            if node_id == node_index[-2]:
                if current_rule_set not in list_of_rules:
                    list_of_rules.append(current_rule_set)
                current_rule_set = []

# print(list_of_rules)
for ruleset in list_of_rules:
    print(ruleset)

rule_df = pd.DataFrame()

# Saving the rule set
# If the rule is composed of encoded thresholds, these are converted to their original meanign
for i, ruleset in enumerate(list_of_rules):
    for rule in ruleset:
        feature = rule['feature']
        greater = rule['greater']
        threshold = rule['threshold']
        rule_df.at[i, str(feature) + '_greater'] = greater
        rule_df.at[i, str(feature) + '_threshold'] = threshold
        if feature in le_encodings.keys():
            rule_df.at[i, str(feature) + '_greater_nonenc'] = greater
            print("DEBUG val " + str(feature))
            print("DEBUG " + str(threshold))
            found_thr = None
            if threshold in le_encodings[feature].keys():
                print("yes")
                found_thr = le_encodings[feature][threshold]

            rule_df.at[i, str(feature) + '_threshold_nonenc'] = found_thr

# Date and time to compare with previous experiments
file_time = str("d"
                + str(datetime.now().day)
                + "-"
                + str(datetime.now().hour)
                + str(datetime.now().minute)
                + str(datetime.now().second))

rule_df.to_csv(output_file
               + "ruleset_"
               + file_time
               + ".csv")

print(rule_df)
print(le_encodings)

# Saving the rule encodings for later use
with open(output_file + 'encoding_' + file_time + '.json', 'w+') as f:
    json.dump(le_encodings, f, indent=4)

# for data_point in y_test.rows:
# This may need to be expanded to multiple trees in the future
#    tree = rfc.estimators_
#    tree.decision_path(data_point)

# for i, tree in enumerate(rfc.estimators_):
#    tree_struct = tree.tree_
#    print(tree_struct.children_left[0])
#    print(tree_struct.children_right[0])
#    print(type(tree))

# fig, axes = plt.subplots(nrows=1, ncols=1, figsize=(4, 4), dpi=800)
# sk.tree.plot_tree(rfc.estimators_[0],
#                  node_ids=True,
#                  feature_names=train_db.columns,
#                  filled=True)
# fig.savefig("rf_individualtree_debug" + str(1337) + ".png")
