# -*- coding: utf-8 -*-
# By:Eastmount CSDN 2023-06-01
import os
import csv
import time
import numpy as np
import seaborn as sns
from sklearn import metrics
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

start = time.clock()
csv.field_size_limit(500 * 1024 * 1024)

#---------------------------第一步 加载数据集------------------------
#训练集
file = "train_dataset.csv"
label_train = []
content_train = []
with open(file, "r") as csv_file:
    csv_reader = csv.reader(csv_file)
    header = next(csv_reader)
    for row in csv_reader:
        label_train.append(row[1])
        value = str(row[3])
        content_train.append(value)
print(label_train[:2])
print(content_train[:2])

#测试集
file = "test_dataset.csv"
label_test = []
content_test = []
with open(file, "r") as csv_file:
    csv_reader = csv.reader(csv_file)
    header = next(csv_reader)
    for row in csv_reader:
        label_test.append(row[1])
        value = str(row[3])
        content_test.append(value)
print(len(label_train),len(label_test))
print(len(content_train),len(content_test)) #1241 650

#---------------------------第二步 向量转换------------------------
contents = content_train + content_test
labels = label_train + label_test

#计算词频 min_df max_df
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(contents)
words = vectorizer.get_feature_names()
print(words[:10])
print("特征词数量:",len(words))

#计算TF-IDF
transformer = TfidfTransformer()
tfidf = transformer.fit_transform(X)
weights = tfidf.toarray()

#---------------------------第三步 编码转换------------------------
le = LabelEncoder()
y = le.fit_transform(labels)
X_train, X_test = weights[:1241], weights[1241:]
y_train, y_test = y[:1241], y[1241:]

#---------------------------第四步 分类检测------------------------
clf = LogisticRegression(solver='liblinear')
clf.fit(X_train, y_train)
pre = clf.predict(X_test)
print(clf)
print(classification_report(y_test, pre, digits=4))
print("accuracy:")
print(metrics.accuracy_score(y_test, pre))

#计算时间
elapsed = (time.clock() - start)
print("Time used:", elapsed)
