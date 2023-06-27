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

start = time.clock()

#---------------------------------------第一步 数据读取------------------------------------
# 读取测数据集
train_df = pd.read_csv("..\\train_dataset.csv")
val_df = pd.read_csv("..\\val_dataset.csv")
test_df = pd.read_csv("..\\test_dataset.csv")
print(train_df.head())

# 解决中文显示问题
plt.rcParams['font.sans-serif'] = ['KaiTi']
plt.rcParams['axes.unicode_minus'] = False

#---------------------------------第二步 OneHotEncoder()编码---------------------------------
# 对数据集的标签数据进行编码  (no apt md5 api)
train_y = train_df.apt
val_y = val_df.apt
test_y = test_df.apt
le = LabelEncoder()
train_y = le.fit_transform(train_y).reshape(-1,1)
val_y = le.transform(val_y).reshape(-1,1)
test_y = le.transform(test_y).reshape(-1,1)
Labname = le.classes_

# 对数据集的标签数据进行one-hot编码
ohe = OneHotEncoder()
train_y = ohe.fit_transform(train_y).toarray()
val_y = ohe.transform(val_y).toarray()
test_y = ohe.transform(test_y).toarray()

#-------------------------------第三步 使用Tokenizer对词组进行编码-------------------------------
# 使用Tokenizer对词组进行编码
max_words = 2000
max_len = 300
tok = Tokenizer(num_words=max_words)

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
with open('tok.pickle', 'wb') as handle:
    pickle.dump(tok, handle, protocol=pickle.HIGHEST_PROTOCOL)
with open('tok.pickle', 'rb') as handle:
    tok = pickle.load(handle)

# 使用tok.texts_to_sequences()将数据转化为序列
train_seq = tok.texts_to_sequences(train_content)
val_seq = tok.texts_to_sequences(val_content)
test_seq = tok.texts_to_sequences(test_content)

# 将每个序列调整为相同的长度
train_seq_mat = sequence.pad_sequences(train_seq,maxlen=max_len)
val_seq_mat = sequence.pad_sequences(val_seq,maxlen=max_len)
test_seq_mat = sequence.pad_sequences(test_seq,maxlen=max_len)

#-------------------------------第四步 建立LSTM模型并训练-------------------------------
num_labels = 5
model = Sequential()
model.add(Embedding(max_words+1, 128, input_length=max_len))
#model.add(Bidirectional(LSTM(128, dropout=0.3, recurrent_dropout=0.1)))
model.add(Bidirectional(LSTM(128)))
model.add(Dense(128, activation='relu'))
model.add(Dropout(0.3))
model.add(Dense(num_labels, activation='softmax'))
model.summary()
model.compile(loss="categorical_crossentropy",
              optimizer='adam',
              metrics=["accuracy"])

flag = "test"
if flag == "train":
    print("模型训练")
    # 模型训练
    model_fit = model.fit(train_seq_mat, train_y, batch_size=64, epochs=15,
                          validation_data=(val_seq_mat,val_y),
                          callbacks=[EarlyStopping(monitor='val_loss',min_delta=0.0001)]
                         )
    
    # 保存模型
    model.save('bilstm_model.h5')  
    del model  # deletes the existing model
    
    # 计算时间
    elapsed = (time.clock() - start)
    print("Time used:", elapsed)
    print(model_fit.history)
    
else:
    print("模型预测")
    model = load_model('bilstm_model.h5')
    
    #--------------------------------------第五步 预测及评估--------------------------------
    # 对测试集进行预测
    test_pre = model.predict(test_seq_mat)
    confm = metrics.confusion_matrix(np.argmax(test_y,axis=1),
                                     np.argmax(test_pre,axis=1))
    print(confm)
    print(metrics.classification_report(np.argmax(test_y,axis=1),
                                        np.argmax(test_pre,axis=1),
                                        digits=4))
    print("accuracy", metrics.accuracy_score(np.argmax(test_y, axis=1),
                                             np.argmax(test_pre, axis=1)))
    # 结果存储
    f1 = open("bilstm_test_pre.txt", "w")
    for n in np.argmax(test_pre, axis=1):
        f1.write(str(n) + "\n")
    f1.close()

    f2 = open("bilstm_test_y.txt", "w")
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
    plt.savefig('bilstm_result.png')
    plt.show()

    #--------------------------------------第六步 验证算法--------------------------------
    # 使用tok对验证数据集重新预处理
    val_seq = tok.texts_to_sequences(val_content)
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
