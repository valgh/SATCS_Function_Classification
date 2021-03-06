# -*- coding: utf-8 -*-
"""CNN_adjmat_CFGS_asm.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1hoYvqr0ohU5HmRjpJSoYwKQAUi39gWLg
"""

# now we can start working with our dataset.
# mounting drive...
from google.colab import drive
drive.mount("/content/gdrive/")

# retrieving the classes
import json
classes = json.load(open("/content/gdrive/My Drive/func_classified_asm_tfidf_10_120000.json", "r"))
print(type(classes))
for centroid in classes:
  print(len(classes[centroid]))
print(classes[str(3)])
print(len(classes[str(3)]))

import json
func2adj_1 = json.load(open("/content/gdrive/My Drive/func2adj_1_t.json", "r"))
func2adj_2 = json.load(open("/content/gdrive/My Drive/func2adj_2_t.json", "r"))
func2adj_3 = json.load(open("/content/gdrive/My Drive/func2adj_3_t.json", "r"))
func2adj_4 = json.load(open("/content/gdrive/My Drive/func2adj_4_t.json", "r"))

import gc
# merging everything
func2adj_1.update(func2adj_2)
func2adj_1.update(func2adj_3)
func2adj_1.update(func2adj_4)
func2adj = func2adj_1
gc.collect()
print(len(func2adj))

class2adj = {}
for centroid in classes:
  class2adj[centroid] = []
  for func in classes[centroid]:
    class2adj[centroid].append(func2adj[func])

to_rem = ['1', '2', '3', '5', '4', '6']
#for centroid in class2adj:
#  if len(class2adj[centroid])>14000 or len(class2adj[centroid])<6000:
#    to_rem.append(centroid)

for i in to_rem:
  class2adj.pop(i)

# balancing the dataset...

for centroid in class2adj:
  class2adj[centroid] = class2adj[centroid][:12280]


for centroid in class2adj:
  print(centroid, len(class2adj[centroid]))

#print(class2adj[str(1)])
#print(class2adj[str(1)][1])

# now we need to split this dataset we obtained,
# and then to make a dataloader for it in order to
# be processed by a CNN.

adj_mats = []
labels = []
for centroid in class2adj:
  for adj_mat in class2adj[centroid]:
    adj_mats.append(adj_mat)
    labels.append(int(centroid))


# now we split our dataset into train, development and test
from sklearn.model_selection import train_test_split
rest_adj, test_adj, rest_labels, test_labels = train_test_split(adj_mats, labels, test_size=0.1, random_state=1)
train_adj, dev_adj, train_labels, dev_labels = train_test_split(rest_adj, rest_labels, test_size=0.1, random_state=1)

print("Train size:", len(train_adj))
print("Dev size:", len(dev_adj)) #not actually used here
print("Test size:", len(test_adj))

# and now we get the number of labels with corresponding indexes
target_names = list(set(labels))
label2idx = {label: idx for idx, label in enumerate(target_names)}
print(label2idx)
print(type(train_adj))
print(type(train_labels))

import numpy as np
to_train_sp = train_adj + dev_adj
to_label = train_labels + dev_labels

# now the adjacency matrices all have different dimension, so
# we need all of them to have the same dimension.
# First, we turn them all into arrays:

to_train = []
for adj_mat_sp in to_train_sp:
  to_train.append(np.array(adj_mat_sp, dtype = np.float64))

print(type(to_train[0]))
print(to_train[0])
print(to_label[0])
print(np.shape(to_train[0]))
print(type(np.shape(to_train[0])))

def max_dim(to_train):
  max = None
  for adj_mat in to_train:
    size = adj_mat.shape
    if max == None:
      max = size
    elif size > max:
      print(size)
      max = size
  return max

print("\n=======MAX LEN MATRIX:==========\n")
d = max_dim(to_train)
print(d)

def padding(m, max_dim):
  z = np.zeros(shape=(max_dim,max_dim), dtype=m.dtype)
  sh = np.shape(m)[0]
  z[:sh,:sh] = m
  return z

print("\n========PCA==========\n")

def PCA_dim(to_train):
  m = 100
  pca_out = []
  for adj_mat in to_train:
    n = adj_mat.shape[0]
    if n > m:
      u,s,vh = np.linalg.svd(adj_mat, full_matrices=False) 
      smat = np.zeros((m*n, n+m), dtype=np.float16)
      smat[:m, :m] = np.diag(s[:m]) # instead of looping through the s array, just exploit the part we need of it
      smat = smat[:m, :m] # here we truncate
      u = u[:m, :m]
      transformed = np.dot(u, smat)
      pca_out.append(transformed[:m, :m])
    else:
      z = padding(adj_mat, m)
      pca_out.append(z)
  return pca_out

pca_out = PCA_dim(to_train)
print(pca_out[0])

X_training = pca_out
print(len(X_training[0]))
for idx in X_training:
  if np.shape(idx)[0] > 100:
    print(np.shape(idx)[0])
  elif np.shape(idx)[0]  < 100:
    print(np.shape(idx)[0])
import gc
gc.collect()

# encoding the labels
def encode_labels(dataset):
  labels = []
  for l in dataset:
    labels.append(label2idx[l])
  return np.asarray(labels)

y_training = encode_labels(to_label)
print(y_training[0])

#now we can create the dataset and the dataloader for Pytorch
import torch
from torch.utils.data import TensorDataset, DataLoader

#Tensor Dataset
train_data = TensorDataset(torch.FloatTensor(X_training), torch.from_numpy(y_training))
print(train_data[0])
#DataLoader
train_loader = DataLoader(train_data, shuffle=True, batch_size=50)
print(train_loader)

# BUILDING UP THE CNN STEP
# now we build up our neural network
import torch
from torch import nn
import torch.nn.functional as F

class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.filters = 128
        self.filters_2 = 256
        self.output = len(class2adj) # number of classes, out features of final layer
        #convolutional layer
        self.conv = nn.Conv2d(1, self.filters, kernel_size=5)
        #another conv layer
        self.conv_2 = nn.Conv2d(self.filters, self.filters_2, kernel_size=5)
        #FULLY CONNECTED LAYER:
        self.fc1 = nn.Linear(self.filters_2, self.output)
        self.softmax = nn.Softmax(1)

    def forward(self, x):
        x = x.unsqueeze(1) #to have an input channel dimension=1 that is the one that conv layer expects,
        x = F.relu(self.conv(x))
        x = F.relu(self.conv_2(x)).squeeze(3) #match size expected from pooling layer
        x = F.max_pool2d(x, x.size(2))
        x = x.view(x.shape[0], -1) #flatten the output of pooling to provide the final fc layer the expected input
        #apply dropout ONLY IF NOT TRAINING
        x = F.dropout(x, training = self.training)
        x = self.fc1(x)
        return self.softmax(x)
#END OF BUILDING UP CNN STEP

#INSTANTIATING THE CNN STEP
#enabling GPU
use_cuda = torch.cuda.is_available()
device = torch.device("cuda" if use_cuda else "cpu")
from torch import nn, optim
net = Net()

net.to(device)

loss = nn.CrossEntropyLoss()
opt = optim.Adam(params=net.parameters(), lr = 0.001)

print(net)

net = net.float()

#DEFINING THE TRAINING STEP
def train_step(x, y):
  net.train()
  y_pred = net(x)
  loss_epoch = loss(y_pred, y)
  loss_epoch.backward()
  opt.step()
  opt.zero_grad()

#TRAINING STEP
import torch
from tqdm import tqdm_notebook as tqdm
for epoch in tqdm(range(20)):
  net.train()
  for Xb, yb in train_loader:
    Xb = Xb.to(device) #move into device 
    yb = yb.to(device) #move into device 
    train_step(Xb, yb)

# now we prepare the test/evaluation dataloader
y_testing = encode_labels(test_labels)
to_test = []
for adj_mat in test_adj:
  to_test.append(np.array(adj_mat, dtype = np.float64))
X_test = to_test
print(y_testing[1])
print(X_test[1])

X_test = PCA_dim(to_test)
#Tensor Dataset
test_data = TensorDataset(torch.FloatTensor(X_test), torch.from_numpy(y_testing))
print(test_data)
print(test_data[1])
#DataLoader
test_loader = DataLoader(test_data, shuffle=True, batch_size=50)
print(test_loader)

# EVALUATION OF THE NETWORK
# now evaluating the performances on the test_dataset
with torch.no_grad():
  Y_pred = []
  Y_true = []
  net.eval()
  for Xb, yb in test_loader:
    Xb = Xb.to(device)
    y_pred = net(Xb)
    yb = yb.to(device)
    correct = (y_pred.max(dim=1)[1] == yb)
    Y_pred.append(y_pred.max(dim=1)[1].cpu())
    Y_true.append(yb.cpu())
  print(torch.mean(correct.float()).item())

from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, classification_report
print(confusion_matrix(torch.cat(Y_true), torch.cat(Y_pred)))

print("\nTest performance:", precision_recall_fscore_support(torch.cat(Y_true), torch.cat(Y_pred), average="micro"))

print(classification_report(torch.cat(Y_true), torch.cat(Y_pred), zero_division=0))
