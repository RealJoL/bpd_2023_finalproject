#!/usr/bin/env python
# coding: utf-8

# In[22]:


from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import json

# In[23]:


json_file_path = "./output/rulenc/nostring/encoding_d13-154428.json"
figure_out_path = "./output/figures/multi/nostring/"

with open(json_file_path, 'r') as j:
    contents = json.loads(j.read())

ruleset_df = pd.read_csv("./output/rulenc/nostring/ruleset_d13-154428.csv", index_col=0)
flow_df = pd.read_csv("capture20110818-2.binetflow")

flow_df['Label'].unique()
malicious = list(filter(lambda x: "Botnet" in x, flow_df['Label'].unique()))

all_bad_db = flow_df[flow_df["Label"].isin(malicious)]
all_good_db = flow_df[~ flow_df["Label"].isin(malicious)]

# Port analysis
good_sport_df = pd.DataFrame(all_good_db['Sport'])

# Fill Sport for null to 0 and convert to int
good_sport_df = pd.DataFrame(good_sport_df['Sport'].fillna(value="0"))
good_sport_df = pd.DataFrame(good_sport_df['Sport'].apply(lambda x: int(int(x, 16))))

n_of_ports = 10
plt.rcParams.update({'font.size': 22})
file_time = str("d"
                + str(datetime.now().day)
                + "-"
                + str(datetime.now().hour)
                + str(datetime.now().minute)
                + str(datetime.now().second))

plt.figure(figsize=(12, 7))

freq_good_sport = good_sport_df['Sport'].value_counts()
red_freq_good_sport = freq_good_sport[0:n_of_ports]

coloured_bars = []
nhit_on_freq_good_sport = {}

for _, ruleset in ruleset_df.iterrows():
    # print(ruleset)
    for port in red_freq_good_sport.index:
        if ruleset['Sport_greater'] is None:
            continue
        if not port in nhit_on_freq_good_sport.keys():
            nhit_on_freq_good_sport[port] = 0
        if ruleset['Sport_greater']:
            if port > ruleset['Sport_threshold']:
                nhit_on_freq_good_sport[port] += 1
        if not ruleset['Sport_greater']:
            if port > ruleset['Sport_threshold']:
                nhit_on_freq_good_sport[port] += 1

# TODO In the future, distinguish by number of hits

for k in nhit_on_freq_good_sport.keys():
    if nhit_on_freq_good_sport[k] > 0:
        coloured_bars.append(k)

good_sport_color = [{f not in nhit_on_freq_good_sport.keys(): 'blue',
                     nhit_on_freq_good_sport[f] == 4: 'orange',
                     nhit_on_freq_good_sport[f] == 5: 'red',
                     nhit_on_freq_good_sport[f] == 0: 'blue',
                     nhit_on_freq_good_sport[f] > 0: 'yellow',
                     nhit_on_freq_good_sport[f] > 5: 'purple',

                     }[True] for f in red_freq_good_sport.index]

good_sport_bar_plot = red_freq_good_sport.plot.bar(color=good_sport_color)

plt.plot(0, 0, 'blue', label='No hits', lw=13)
plt.plot(0, 0, 'yellow', label='0-3 hits', lw=13)
plt.plot(0, 0, 'orange', label='4 hits', lw=13)
plt.plot(0, 0, 'red', label='5 hits', lw=13)
plt.plot(0, 0, 'purple', label='More than 5 hits', lw=13)
plt.legend(fontsize=18)

label_to_remove = 'Sport'
h, l = good_sport_bar_plot.get_legend_handles_labels()

idx_keep = [k[0] for k in enumerate(l) if l[k[0]] != label_to_remove]

handles = []
labels = []

for i in idx_keep:
    handles.append(h[i])
    labels.append(l[i])
good_sport_bar_plot.legend(handles, labels, prop={'size': 20})
plt.title("Rule hits per src_port on benign flows \n n: " + str(len(ruleset_df)) + ", top " + str(
    n_of_ports) + " most frequent ports",
          fontsize=20)
good_sport_bar_plot.tick_params(axis='both', which='major', labelsize=13)
plt.savefig(figure_out_path + "fig_good_sport_" + file_time + ".png", transparent=True)
plt.show()

# In[29]:


# Below here is the same analysis as above, but for Dport

# In[30]:


# Port analysis
good_dport_df = pd.DataFrame(all_good_db['Dport'])

# Fill Sport for null to 0 and convert to int
good_dport_df = pd.DataFrame(good_dport_df['Dport'].fillna(value="0"))
good_dport_df = pd.DataFrame(good_dport_df['Dport'].apply(lambda x: int(int(x, 16))))

# In[31]:


plt.figure(figsize=(12, 7))

freq_good_dport = good_dport_df['Dport'].value_counts()
red_freq_good_dport = freq_good_dport[0:n_of_ports]

coloured_bars_good_dport = []
nhit_on_freq_good_dport = {}

for _, ruleset in ruleset_df.iterrows():
    # print(ruleset)
    for port in red_freq_good_dport.index:
        if ruleset['Dport_greater'] is None:
            continue
        if not port in nhit_on_freq_good_dport.keys():
            nhit_on_freq_good_dport[port] = 0
        if ruleset['Dport_greater']:
            if port > ruleset['Dport_threshold']:
                nhit_on_freq_good_dport[port] += 1
        if not ruleset['Dport_greater']:
            if port > ruleset['Dport_threshold']:
                nhit_on_freq_good_dport[port] += 1

for k in nhit_on_freq_good_dport.keys():
    if nhit_on_freq_good_dport[k] > 0:
        coloured_bars_good_dport.append(k)

good_dport_color = [{f not in nhit_on_freq_good_dport.keys(): 'blue',
                     nhit_on_freq_good_dport[f] == 0: 'blue',
                     nhit_on_freq_good_dport[f] > 0: 'yellow',
                     nhit_on_freq_good_dport[f] == 4: 'orange',
                     nhit_on_freq_good_dport[f] == 5: 'red',
                     }[True] for f in red_freq_good_dport.index]

good_dport_bar_plot = red_freq_good_dport.plot.bar(color=good_dport_color)

plt.plot(0, 0, 'blue', label='No hits', lw=13)
plt.plot(0, 0, 'yellow', label='0-3 hits', lw=13)
plt.plot(0, 0, 'orange', label='4 hits', lw=13)
plt.plot(0, 0, 'red', label='5 hits', lw=13)
plt.plot(0, 0, 'purple', label='More than 5 hits', lw=13)
plt.legend(fontsize=18)

label_to_remove = 'Dport'
h, l = good_dport_bar_plot.get_legend_handles_labels()

idx_keep = [k[0] for k in enumerate(l) if l[k[0]] != label_to_remove]

handles = []
labels = []

for i in idx_keep:
    handles.append(h[i])
    labels.append(l[i])
good_dport_bar_plot.legend(handles, labels, prop={'size': 20})
good_dport_bar_plot.tick_params(axis='both', which='major', labelsize=13)
plt.title("Rule hits per dst_port on benign flows \n n: " + str(len(ruleset_df)) + ", top " + str(
    n_of_ports) + " most frequent ports",
          fontsize=20)

plt.savefig(figure_out_path + "fig_good_dport_" + file_time + ".png", transparent=True)
plt.show()

# Port analysis
bad_dport_df = pd.DataFrame(all_bad_db['Dport'])

# Fill Sport for null to 0 and convert to int
bad_dport_df = pd.DataFrame(bad_dport_df['Dport'].fillna(value="0"))
bad_dport_df = pd.DataFrame(bad_dport_df['Dport'].apply(lambda x: int(int(str(x), 16))))

# In[34]:


plt.figure(figsize=(12, 7))

freq_bad_dport = bad_dport_df['Dport'].value_counts()
red_freq_bad_dport = freq_bad_dport[0:n_of_ports]

coloured_bars_bad_dport = []
nhit_on_freq_bad_dport = {}

for _, ruleset in ruleset_df.iterrows():
    # print(ruleset)
    for port in red_freq_bad_dport.index:
        if ruleset['Dport_greater'] is None:
            continue
        if not port in nhit_on_freq_bad_dport.keys():
            nhit_on_freq_bad_dport[port] = 0
        if ruleset['Dport_greater']:
            if port > ruleset['Dport_threshold']:
                nhit_on_freq_bad_dport[port] += 1
        if not ruleset['Dport_greater']:
            if port > ruleset['Dport_threshold']:
                nhit_on_freq_bad_dport[port] += 1

for k in nhit_on_freq_bad_dport.keys():
    if nhit_on_freq_bad_dport[k] > 0:
        coloured_bars_bad_dport.append(k)

bad_dport_color = [{f not in nhit_on_freq_bad_dport.keys(): 'blue',
                    nhit_on_freq_bad_dport[f] == 0: 'blue',
                    nhit_on_freq_bad_dport[f] > 0: 'yellow',
                    nhit_on_freq_bad_dport[f] == 4: 'orange',
                    nhit_on_freq_bad_dport[f] == 5: 'red',
                    nhit_on_freq_bad_dport[f] > 5: 'purple',
                    }[True] for f in red_freq_bad_dport.index]

bad_dport_bar_plot = red_freq_bad_dport.plot.bar(color=bad_dport_color)

plt.plot(0, 0, 'blue', label='No hits', lw=13)
plt.plot(0, 0, 'yellow', label='0-3 hits', lw=13)
plt.plot(0, 0, 'orange', label='4 hits', lw=13)
plt.plot(0, 0, 'red', label='5 hits', lw=13)
plt.plot(0, 0, 'purple', label='More than 5 hits', lw=13)
plt.legend(fontsize=18)

label_to_remove = 'Dport'
h, l = bad_dport_bar_plot.get_legend_handles_labels()

idx_keep = [k[0] for k in enumerate(l) if l[k[0]] != label_to_remove]

handles = []
labels = []

for i in idx_keep:
    handles.append(h[i])
    labels.append(l[i])
bad_dport_bar_plot.legend(handles, labels, prop={'size': 20})

bad_dport_bar_plot.tick_params(axis='both', which='major', labelsize=13)
plt.title("Rule hits per dst_port on malicious flows \n n: " + str(len(ruleset_df)) + ", top " + str(
    n_of_ports) + " most frequent ports",
          fontsize=20)
plt.savefig(figure_out_path + "fig_bad_dport_" + file_time + ".png", transparent=True)
plt.show()

# Port analysis
bad_sport_df = pd.DataFrame(all_bad_db['Sport'])

# Fill Sport for null to 0 and convert to int
bad_sport_df = pd.DataFrame(bad_sport_df['Sport'].fillna(value="0"))
bad_sport_df = pd.DataFrame(bad_sport_df['Sport'].apply(lambda x: int(int(str(x), 16))))

plt.figure(figsize=(12, 7))

freq_bad_sport = bad_sport_df['Sport'].value_counts()
red_freq_bad_sport = freq_bad_sport[0:n_of_ports]

coloured_bars_bad_sport = []
nhit_on_freq_bad_sport = {}

for _, ruleset in ruleset_df.iterrows():
    # print(ruleset)
    for port in red_freq_bad_sport.index:
        if ruleset['Sport_greater'] is None:
            continue
        if not port in nhit_on_freq_bad_sport.keys():
            nhit_on_freq_bad_sport[port] = 0
        if ruleset['Sport_greater']:
            if port > ruleset['Sport_threshold']:
                nhit_on_freq_bad_sport[port] += 1
        if not ruleset['Sport_greater']:
            if port > ruleset['Sport_threshold']:
                nhit_on_freq_bad_sport[port] += 1

for k in nhit_on_freq_bad_sport.keys():
    if nhit_on_freq_bad_sport[k] > 0:
        coloured_bars_bad_sport.append(k)

bad_sport_color = [{f not in nhit_on_freq_bad_sport.keys(): 'blue',
                    nhit_on_freq_bad_sport[f] == 4: 'orange',
                    nhit_on_freq_bad_sport[f] == 5: 'red',
                    nhit_on_freq_bad_sport[f] == 0: 'blue',
                    nhit_on_freq_bad_sport[f] > 0: 'yellow',
                    nhit_on_freq_bad_sport[f] > 5: 'purple',

                    }[True] for f in red_freq_bad_sport.index]

bad_sport_bar_plot = red_freq_bad_sport.plot.bar(color=bad_sport_color)

plt.plot(0, 0, 'blue', label='No hits', lw=13)
plt.plot(0, 0, 'yellow', label='0-3 hits', lw=13)
plt.plot(0, 0, 'orange', label='4 hits', lw=13)
plt.plot(0, 0, 'red', label='5 hits', lw=13)
plt.plot(0, 0, 'purple', label='More than 5 hits', lw=13)
plt.legend(fontsize=18)

label_to_remove = 'Sport'
h, l = bad_sport_bar_plot.get_legend_handles_labels()

idx_keep = [k[0] for k in enumerate(l) if l[k[0]] != label_to_remove]

handles = []
labels = []

for i in idx_keep:
    handles.append(h[i])
    labels.append(l[i])
bad_sport_bar_plot.legend(handles, labels, prop={'size': 20})

bad_sport_bar_plot.tick_params(axis='both', which='major', labelsize=13)
plt.title("Rule hits per src_port on malicious flows \n n: " + str(len(ruleset_df)) + ", top " + str(
    n_of_ports) + " most frequent ports",
          fontsize=20)
plt.savefig(figure_out_path + "fig_bad_sport_" + file_time + ".png", transparent=True)
plt.show()
