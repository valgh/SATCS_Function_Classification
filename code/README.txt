This folder contains the Python code of the notebooks executed in Colab.
The code in each of the .py files is meant to be executed in Colab environment.

Each of the .py files connects, when executed in Colab, to Google Drive of the user,
under which the user must have the files requested.

Please notice also that some of the files reported to be saved/loaded from the Drive in this code do not correspond to the 
files under the json_files folder. This is due to the fact that those files are actually the result of 
several runs of each of these .py files, given the limits of the Colab machines: files had to be computed
separately in separate runs and then merged together.

With respect to the Report.pdf, the .py files perform the following operations:


unstrip.sh -> operations in paragraph 2: given the dataset of binaries, unstrip them according to their debug files
analyze_headless.py and extract_cfgs.py -> operations in paragraph 2: execute Ghidra in Headless Analysis mode and extract the desired features from each binary. Outputs JSON files containing features for each different function.
asm_instructions_extraction_autoencoder_bow_asm.py -> operations in paragraph 2 and 3: text assembly instructions extraction from JSON files, BOW encodings with Autoencoder
autoencoder_tfidf_asm.py -> operations in paragraph 3: TFIDF encodings of functions with Autoencoder
kmeans_asm.py -> operations in paragraph 3: k-means++ for clusters retrieval over BOW or TFIDF encodings
preprocessing_adjmat_asm.py -> operations in paragraph 4: recovering topologically ordered adjacency amtrices from CFGs per each fucntion
cnn_adjmat_cfgs_asm.py -> implementation of paragraph 4 CNN 
preprocessing_randwalk_doc2vec_asm.py -> operations in paragraph 5: recovering topologically ordered transition matrices, computing random walks per each CFG and doc2vec node embeddings over asm instructions
lstm_embeddings_cfgs_asm.py -> implementation of paragraph 6 Bi-LSTM
cnn_randwalk_embeddings_cfgs_asm.py -> implementation of paragraph 6 CNN
