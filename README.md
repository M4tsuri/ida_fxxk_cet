# ida_fxxk_cet
解决IDA Pro 7.0版本在遇到使用CET技术的ELF文件时符号解析错误的问题

症状：打开ELF文件时IDA报错：`Unexpected plt stub`，且符号解析不正确，如下图所示（2020 ciscn final Day1 server）：

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gja6y49g95j31c00u0npd.jpg)

使用方法：在file->Script File...中运行该脚本。

效果如下：

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gja70djvtmj31c00u0b29.jpg)