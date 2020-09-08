# -*- coding: utf-8 -*-
"""preprocessing_randwalk_doc2vec_asm.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1at9xXQDWZRY61Ts6Vr4PXMBaxR8H0cMB
"""

# mounting drive...
from google.colab import drive
drive.mount("/content/gdrive/")

# reload all the json files obtained sequentially, execution after execution
import json
func_dict = json.load(open("/content/gdrive/My Drive/func_dict_raw_4.json", "r"))
print(len(func_dict))

# we now process further the previous dictionary: we want
# a dictionary so that we have: FUNC_NAME -> LIST OF ASM INSTRUCTIONS
import networkx as nx
from networkx.readwrite import json_graph

func_dict_filtered = {}
i=0
for func_name in func_dict:
  i+=1
  if (i==1000):
    print("reporting...\n")
    i=0
  list_asm_instructions = []
  G = json_graph.node_link_graph(func_dict[func_name])
  for node in G.nodes.data():
    dict_string = node[1]['data']['asm_dict_string']
    for addr in dict_string:
      list_asm_instructions.append(dict_string[addr])
  func_dict_filtered[func_name] = list_asm_instructions
# print(func_dict_filtered['abort'])

# we now create the vocabulary (wrap)
def filter(func_dict_filtered):
  func_dict_final = {}
  for func in func_dict_filtered:
    func_dict_final[func] = []
    for inst in func_dict_filtered[func]:
      inst_f = inst.split()[0]
      func_dict_final[func].append(inst_f)
  return func_dict_final

func_dict_final = filter(func_dict_filtered)

for func in func_dict_final:
  print(func_dict_filtered[func])
  print(func_dict_final[func])
  break

texts = []
for func in func_dict_final:
  texts.append(func_dict_final[func])
print(len(texts))

# here we exploit doc2vec
import gensim
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
for_vocab = [TaggedDocument(doc, [i]) for i, doc in enumerate(texts)]
d2v = gensim.models.Doc2Vec(vector_size=100, window=5, min_count=1, workers=4)
d2v.build_vocab(for_vocab)
d2v.train(for_vocab, total_examples=d2v.corpus_count, epochs=d2v.epochs)

print(d2v)

vector = d2v.infer_vector(["JMP", "MOV", "ADD"])
print(vector)

# so this is what we need to do now:
# for each FUNC_NAME in CLASSES, retrieve its ADJACENCY MATRIX
# and then build a dictionary so that we have CLASS -> LIST OF FUNCTIONS AS ADJ MATRICES
# we do this first for the adjacency matrices ordered in topological fashion,
# then in the next block we do the same but without topological order for what's to come next
func2adj = {}
func2entrypoint = {}
for func in func_dict:
  G = json_graph.node_link_graph(func_dict[func])
  attr = nx.get_node_attributes(G, 'entrypoint')
  for node in attr:
    if attr[node] == True:
      for index, n in enumerate(G.nodes()):
        if n == node:
          func2entrypoint[func] = index
          break
      break
  adj_mat = nx.adjacency_matrix(G).todense()
  func2adj[func] = adj_mat.tolist()

# here we perform the random walk on the google_matrix with teleportation
# prob. = 0, so it's basically a classic transition matrix,
# and encode each node with the assembly instructions inside of it
# each graph is encoded as a sequence of indexes corresponding to its nodes
# embeddings

import json
import networkx as nx
from networkx.readwrite import json_graph
import numpy as np
import random
import gc
gc.collect()

# we first get the acyclic directed graphs, then sort them via topological ordering
# and then compute their transition matrixes.
# with the topological sort list, this gets a CFG and it returns a related adjacency matrix with the special property
# that if node x is in list in position j, than any node in a position i>j is either after x in a topological sort
# or is uncomparable in the topological sort

def get_back_edges(G,source):
    if source is None:
        # produce edges for all components
        nodes = G
    else:
        # produce edges for components with source
        nodes = [source]
    visited=set()
    back_edges=set()
    for start in nodes:
        if start in visited:
            continue
        visited.add(start)
        stack = [(start,iter(G[start]))]
        while stack:
            parent,children = stack[-1]
            try:
                child = next(children)
                if child not in visited:
                    visited.add(child)
                    stack.append((child,iter(G[child])))
                else:
                    #detecting if a backedge
                    loop=[]
                    for x in reversed(stack):
                        loop.append(x[0])
                        if x[0] == child:
                            yield (loop,(parent,child))
                            break
            except StopIteration:
                stack.pop()


#takes an input a CFG and it removes all back edges
def cfg_to_dacfg_trivial(G, entrypoint):
    back_edges=[ x for x in get_back_edges(G,entrypoint)]
    edges=[x[1] for x in back_edges]
    for x in edges:
        G.remove_edge(x[0], x[1])
    return G

def get_entrypoint(cfg):
    entrypoint=None
    for x in cfg.nodes(data=True):
        if x[1]['entrypoint']==True:
            entrypoint=x[0]
            break
    return entrypoint

def g_mat(G, poset):
  r = nx.google_matrix(G, nodelist=poset, alpha=1) # teleportation probability is 1-alpha so 0
  return r

func_t = {}

for func in func_dict:
  G = json_graph.node_link_graph(func_dict[func])
  attr = nx.get_node_attributes(G, 'entrypoint')
  e = get_entrypoint(G)
  G = cfg_to_dacfg_trivial(G, e)
  poset = list(nx.topological_sort(G))
  func_t[func] = g_mat(G, poset)

print(len(func_t))

import gc
gc.collect()

# random walk

def random_walk_G(G, graph, vocab, id, entrypoint, walkLength):
  p = G[entrypoint].reshape(-1,1)
  rand_walk = []
  node2idx = {}
  for k in range(walkLength):
    # choose the node with higher probability as the visited node
    # there may be more than one node with same higher probability,
    # so we randomly choose the node among this set of high prob.nodes
    higher_nodes = list()
    idx=0
    for x in np.nditer(p):
      if not higher_nodes:
        if x>0:
          higher_nodes.append(idx)
          idx+=1
      elif x>=np.argmax(higher_nodes):
        higher_nodes.append(idx)
        idx+=1
    if not higher_nodes:
      v = np.argmax(p)
    else:
      v = random.choice(higher_nodes)
    p = G[v]
    hex_addr = list(enumerate(graph.nodes))[v][1]
    ls = list(graph.nodes[hex_addr]['data']['asm_dict_string'].values())
    list_instructions = []
    for el in ls:
      el = el.split()[0]
      list_instructions.append(el)
    embed = d2v.infer_vector(list_instructions).tolist()
    if int(v) not in node2idx:
      vocab[id] = embed
      node2idx[int(v)] = id
      rand_walk.append(id)
      id+=1
    else:
      node2idx[int(v)] = int(v)
      rand_walk.append(int(v))
  return rand_walk, id

# say we do a random walk of fixed length on each CFG now
walkLength = 100
func2walk = {}
func2walkG = {}
vocab = {} 
id = 170985
for func in func_t:
  if func not in func2walkG and func in func2entrypoint:
    G = json_graph.node_link_graph(func_dict[func])
    func2walkG[func], id = random_walk_G(func_t[func], G, vocab, id, func2entrypoint[func], walkLength)
#print(func2walk['abort'])
#print(func2G['abort'])
#print(func2walkG['abort'])

import gc
gc.collect()
print(len(vocab))
print(id)
for idx in vocab:
  if len(vocab[idx]) > 100:
    print('.')

# save everything
# 206535 number of nodes in vocab
json.dump(vocab, open("/content/gdrive/My Drive/vocab_nodes_4.json", "w"))
json.dump(func2walkG, open("/content/gdrive/My Drive/func2walkG_4.json", "w"))