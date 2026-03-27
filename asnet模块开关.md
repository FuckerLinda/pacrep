添加了如下模块，进入asnet模式

deepnet/model/css.py

deepnet/model/asnet.py



3\. deepnet/recognition.py



这是最关键的改动文件之一。

因为 ASNet 和 PacRep 最大的工程差别，不在底层 BERT，而在于：



ASNet 需要 prompt 输入



你手头那份 asnet.py 已经写死了它会从 batch 里拿 prompt 相关输入。

所以 recognition.py 必须改，不能再只准备文本 token 和长度。



4\. run\_train.py



只需要改一处：

把 model\_type 的 choices 增加 "ASNet"，这样你才能用：



python run\_train.py --model\_type ASNet







