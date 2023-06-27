# -*- coding: utf-8 -*-
# By:Eastmount CSDN 2023-06-27
import pickle
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn import metrics
import tensorflow as tf
from sklearn.preprocessing import LabelEncoder,OneHotEncoder
from keras.models import Model
from keras.layers import LSTM, Activation, Dense, Dropout, Input, Embedding
from keras.layers import Convolution1D, MaxPool1D, Flatten
from keras.optimizers import RMSprop
from keras.layers import Bidirectional
from keras.preprocessing.text import Tokenizer
from keras.preprocessing import sequence
from keras.callbacks import EarlyStopping
from keras.models import load_model
from keras.models import Sequential
from keras.layers.merge import concatenate
import time

"""
import os
os.environ["CUDA_DEVICES_ORDER"] = "PCI_BUS_IS"
os.environ["CUDA_VISIBLE_DEVICES"] = "0"
gpu_options = tf.GPUOptions(per_process_gpu_memory_fraction=0.8)
sess = tf.Session(config=tf.ConfigProto(gpu_options=gpu_options))
"""

start = time.clock()

#---------------------------------------第一步 数据读取------------------------------------
# 读取测数据集
train_df = pd.read_csv("..\\train_dataset.csv")
val_df = pd.read_csv("..\\val_dataset.csv")
test_df = pd.read_csv("..\\test_dataset.csv")

# 指定数据类型 否则AttributeError: 'float' object has no attribute 'lower' 存在文本为空的现象
# train_df.SentimentText = train_df.SentimentText.astype(str)
print(train_df.head())

# 解决中文显示问题
plt.rcParams['font.sans-serif'] = ['KaiTi']   #指定默认字体 SimHei黑体
plt.rcParams['axes.unicode_minus'] = False    #解决保存图像是负号'

#---------------------------------第二步 OneHotEncoder()编码---------------------------------
# 对数据集的标签数据进行编码  (no apt md5 api)
train_y = train_df.apt
print("Label:")
print(train_y[:10])
val_y = val_df.apt
test_y = test_df.apt
le = LabelEncoder()
train_y = le.fit_transform(train_y).reshape(-1,1)
print("LabelEncoder")
print(train_y[:10])
print(len(train_y))
val_y = le.transform(val_y).reshape(-1,1)
test_y = le.transform(test_y).reshape(-1,1)
Labname = le.classes_
print(Labname)

# 对数据集的标签数据进行one-hot编码
ohe = OneHotEncoder()
train_y = ohe.fit_transform(train_y).toarray()
val_y = ohe.transform(val_y).toarray()
test_y = ohe.transform(test_y).toarray()
print("OneHotEncoder:")
print(train_y[:10])

#-------------------------------第三步 使用Tokenizer对词组进行编码-------------------------------
# 使用Tokenizer对词组进行编码
# 当我们创建了一个Tokenizer对象后，使用该对象的fit_on_texts()函数，以空格去识别每个词
# 可以将输入的文本中的每个词编号，编号是根据词频的，词频越大，编号越小
max_words = 1000
max_len = 200
tok = Tokenizer(num_words=max_words)  #使用的最大词语数为1000
print(train_df.api[:5])
print(type(train_df.api))

# 提取token：api
train_value = train_df.api
train_content = [str(a) for a in train_value.tolist()]
val_value = val_df.api
val_content = [str(a) for a in val_value.tolist()]
test_value = test_df.api
test_content = [str(a) for a in test_value.tolist()]
tok.fit_on_texts(train_content)
print(tok)

# 保存训练好的Tokenizer和导入
# saving
with open('tok.pickle', 'wb') as handle:
    pickle.dump(tok, handle, protocol=pickle.HIGHEST_PROTOCOL)
# loading
with open('tok.pickle', 'rb') as handle:
    tok = pickle.load(handle)

# 使用word_index属性可以看到每次词对应的编码
# 使用word_counts属性可以看到每个词对应的频数
for ii,iterm in enumerate(tok.word_index.items()):
    if ii < 10:
        print(iterm)
    else:
        break
print("===================")  
for ii,iterm in enumerate(tok.word_counts.items()):
    if ii < 10:
        print(iterm)
    else:
        break

# 使用tok.texts_to_sequences()将数据转化为序列
# 使用sequence.pad_sequences()将每个序列调整为相同的长度
# 对每个词编码之后，每句新闻中的每个词就可以用对应的编码表示，即每条新闻可以转变成一个向量了
train_seq = tok.texts_to_sequences(train_content)
val_seq = tok.texts_to_sequences(val_content)
test_seq = tok.texts_to_sequences(test_content)

# 将每个序列调整为相同的长度
train_seq_mat = sequence.pad_sequences(train_seq,maxlen=max_len)
val_seq_mat = sequence.pad_sequences(val_seq,maxlen=max_len)
test_seq_mat = sequence.pad_sequences(test_seq,maxlen=max_len)
print(train_seq_mat.shape)  #(1241, 200)
print(val_seq_mat.shape)    #(459, 200)
print(test_seq_mat.shape)   #(650, 200)
print(train_seq_mat[:2])

#-------------------------------第四步 建立CNN模型并训练-------------------------------
num_labels = 5
inputs = Input(name='inputs',shape=[max_len], dtype='float64')

# 词嵌入（使用预训练的词向量）
layer = Embedding(max_words+1, 256, input_length=max_len, trainable=False)(inputs)

# 词窗大小分别为3,4,5
cnn = Convolution1D(256, 3, padding='same', strides = 1, activation='relu')(layer)
cnn = MaxPool1D(pool_size=3)(cnn)

# 合并三个模型的输出向量
flat = Flatten()(cnn) 
drop = Dropout(0.4)(flat)
main_output = Dense(num_labels, activation='softmax')(drop)
model = Model(inputs=inputs, outputs=main_output)
model.summary()
model.compile(loss="categorical_crossentropy",
              optimizer='adam',      #RMSprop()
              metrics=["accuracy"])

# 增加判断 防止再次训练
flag = "test"
if flag == "train":
    print("模型训练")
    # 模型训练
    model_fit = model.fit(train_seq_mat, train_y, batch_size=64, epochs=15,
                          validation_data=(val_seq_mat,val_y),
                          callbacks=[EarlyStopping(monitor='val_loss',min_delta=0.001)]   #当val-loss不再提升时停止训练 0.0001
                         )
    
    # 保存模型
    model.save('cnn_model.h5')  
    del model  # deletes the existing model
    
    # 计算时间
    elapsed = (time.clock() - start)
    print("Time used:", elapsed)
    print(model_fit.history)
    
else:
    print("模型预测")
    # 导入已经训练好的模型
    model = load_model('cnn_model.h5')
    
    #--------------------------------------第五步 预测及评估--------------------------------
    # 对测试集进行预测
    test_pre = model.predict(test_seq_mat)
    
    # 评价预测效果，计算混淆矩阵
    confm = metrics.confusion_matrix(np.argmax(test_y,axis=1),
                                     np.argmax(test_pre,axis=1))
    print(confm)
    print(metrics.classification_report(np.argmax(test_y,axis=1),
                                        np.argmax(test_pre,axis=1),
                                        digits=4))
    print("accuracy", metrics.accuracy_score(np.argmax(test_y, axis=1),
                                             np.argmax(test_pre, axis=1)))
    # 结果存储
    f1 = open("cnn_test_pre.txt", "w")
    for n in np.argmax(test_pre, axis=1):
        f1.write(str(n) + "\n")
    f1.close()

    f2 = open("cnn_test_y.txt", "w")
    for n in np.argmax(test_y, axis=1):
        f2.write(str(n) + "\n")
    f2.close()

    plt.figure(figsize=(8,8))
    sns.heatmap(confm.T, square=True, annot=True,
                fmt='d', cbar=False, linewidths=.6,
                cmap="YlGnBu")
    plt.xlabel('True label',size = 14)
    plt.ylabel('Predicted label', size = 14)
    plt.xticks(np.arange(5)+0.5, Labname, size = 12)
    plt.yticks(np.arange(5)+0.5, Labname, size = 12)
    plt.savefig('cnn_result.png')
    plt.show()

    #--------------------------------------第六步 验证算法--------------------------------
    # 使用tok对验证数据集重新预处理
    val_seq = tok.texts_to_sequences(val_content)
    # 将每个序列调整为相同的长度
    val_seq_mat = sequence.pad_sequences(val_seq,maxlen=max_len)
    # 对验证集进行预测
    val_pre = model.predict(val_seq_mat)
    print(metrics.classification_report(np.argmax(val_y,axis=1),
                                        np.argmax(val_pre,axis=1),
                                        digits=4))
    print("accuracy", metrics.accuracy_score(np.argmax(val_y, axis=1),
                                             np.argmax(val_pre, axis=1)))
    # 计算时间
    elapsed = (time.clock() - start)
    print("Time used:", elapsed)
