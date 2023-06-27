# -*- coding: utf-8 -*-
# By:Eastmount CSDN 2023-06-27
import pickle
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import tensorflow as tf
from sklearn import metrics
from sklearn.preprocessing import LabelEncoder,OneHotEncoder
from keras.models import Model
from keras.layers import LSTM, GRU, Activation, Dense, Dropout, Input, Embedding
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
max_words = 1000
max_len = 100
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

#-------------------------------第四步 建立Attention机制-------------------------------
"""
由于Keras目前还没有现成的Attention层可以直接使用，我们需要自己来构建一个新的层函数。
  Keras自定义的函数主要分为四个部分，分别是：
  init：初始化一些需要的参数
  bulid：具体来定义权重是怎么样的
  call：核心部分，定义向量是如何进行运算的
  compute_output_shape：定义该层输出的大小

推荐文章 https://blog.csdn.net/huanghaocs/article/details/95752379
推荐文章 https://zhuanlan.zhihu.com/p/29201491
"""
# Hierarchical Model with Attention
from keras import initializers
from keras import constraints
from keras import activations
from keras import regularizers
from keras import backend as K
from keras.engine.topology import Layer

K.clear_session()

class AttentionLayer(Layer):
    def __init__(self, attention_size=None, **kwargs):
        self.attention_size = attention_size
        super(AttentionLayer, self).__init__(**kwargs)
        
    def get_config(self):
        config = super().get_config()
        config['attention_size'] = self.attention_size
        return config
        
    def build(self, input_shape):
        assert len(input_shape) == 3
        
        self.time_steps = input_shape[1]
        hidden_size = input_shape[2]
        if self.attention_size is None:
            self.attention_size = hidden_size
            
        self.W = self.add_weight(name='att_weight', shape=(hidden_size, self.attention_size),
                                initializer='uniform', trainable=True)
        self.b = self.add_weight(name='att_bias', shape=(self.attention_size,),
                                initializer='uniform', trainable=True)
        self.V = self.add_weight(name='att_var', shape=(self.attention_size,),
                                initializer='uniform', trainable=True)
        super(AttentionLayer, self).build(input_shape)

    #解决方法: Attention The graph tensor has name: model/attention_layer/Reshape:0
    #https://blog.csdn.net/weixin_54227557/article/details/129898614
    def call(self, inputs):
        #self.V = K.reshape(self.V, (-1, 1))
        V = K.reshape(self.V, (-1, 1))
        H = K.tanh(K.dot(inputs, self.W) + self.b)
        #score = K.softmax(K.dot(H, self.V), axis=1)
        score = K.softmax(K.dot(H, V), axis=1)
        outputs = K.sum(score * inputs, axis=1)
        return outputs
    
    def compute_output_shape(self, input_shape):
        return input_shape[0], input_shape[2]

#-------------------------------第五步 建立Attention+CNN模型并训练-------------------------------
# 构建TextCNN模型
num_labels = 5
inputs = Input(name='inputs',shape=[max_len], dtype='float64')
layer = Embedding(max_words+1, 256, input_length=max_len, trainable=False)(inputs)
cnn1 = Convolution1D(256, 3, padding='same', strides = 1, activation='relu')(layer)
cnn1 = MaxPool1D(pool_size=4)(cnn1)
cnn2 = Convolution1D(256, 4, padding='same', strides = 1, activation='relu')(layer)
cnn2 = MaxPool1D(pool_size=4)(cnn2)
cnn3 = Convolution1D(256, 5, padding='same', strides = 1, activation='relu')(layer)
cnn3 = MaxPool1D(pool_size=4)(cnn3)

# 合并三个模型的输出向量
cnn = concatenate([cnn1,cnn2,cnn3], axis=-1)

# BiLSTM+Attention
#bilstm = Bidirectional(LSTM(100, dropout=0.2, recurrent_dropout=0.1, return_sequences=True))(cnn)
bilstm = Bidirectional(LSTM(128, return_sequences=True))(cnn)  #参数保持维度3
layer = Dense(128, activation='relu')(bilstm)
layer = Dropout(0.3)(layer)
attention = AttentionLayer(attention_size=50)(layer)

output = Dense(num_labels, activation='softmax')(attention)
model = Model(inputs=inputs, outputs=output)
model.summary()
model.compile(loss="categorical_crossentropy",
              optimizer='adam',
              metrics=["accuracy"])


flag = "test"
if flag == "train":
    print("模型训练")
    # 模型训练
    model_fit = model.fit(train_seq_mat, train_y, batch_size=128, epochs=15,
                          validation_data=(val_seq_mat,val_y),
                          callbacks=[EarlyStopping(monitor='val_loss',min_delta=0.0005)]
                         )

    # 保存模型
    model.save('cnn_bilstm_model.h5')
    del model  # deletes the existing model
    
    #计算时间
    elapsed = (time.clock() - start)
    print("Time used:", elapsed)
    print(model_fit.history)
    
else:
    print("模型预测")
    model = load_model('cnn_bilstm_model.h5', custom_objects={'AttentionLayer': AttentionLayer(50)}, compile=False)

    #--------------------------------------第六步 预测及评估--------------------------------
    # 对测试集进行预测
    test_pre = model.predict(test_seq_mat)
    confm = metrics.confusion_matrix(np.argmax(test_y,axis=1),np.argmax(test_pre,axis=1))
    print(confm)
    print(metrics.classification_report(np.argmax(test_y,axis=1),
                                        np.argmax(test_pre,axis=1),
                                        digits=4))
    print("accuracy",metrics.accuracy_score(np.argmax(test_y,axis=1),
                                 np.argmax(test_pre,axis=1)))
    # 结果存储
    f1 = open("cnn_bilstm_test_pre.txt", "w")
    for n in np.argmax(test_pre, axis=1):
        f1.write(str(n) + "\n")
    f1.close()

    f2 = open("cnn_bilstm_test_y.txt", "w")
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
    plt.savefig('cnn_bilstm_result.png')
    plt.show()

    #--------------------------------------第七步 验证算法--------------------------------
    # 使用tok对验证数据集重新预处理，并使用训练好的模型进行预测
    val_seq = tok.texts_to_sequences(val_content)
    val_seq_mat = sequence.pad_sequences(val_seq,maxlen=max_len)
    
    # 对验证集进行预测
    val_pre = model.predict(val_seq_mat)
    print(metrics.classification_report(np.argmax(val_y, axis=1),
                                        np.argmax(val_pre, axis=1),
                                        digits=4))
    print("accuracy", metrics.accuracy_score(np.argmax(val_y, axis=1),
                                             np.argmax(val_pre, axis=1)))
    # 计算时间
    elapsed = (time.clock() - start)
    print("Time used:", elapsed)
