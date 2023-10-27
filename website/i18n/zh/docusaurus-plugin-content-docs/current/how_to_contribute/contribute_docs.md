---
title: 贡献文档
sidebar_position: 2
---

# 贡献文档

TQUIC文档主要分为以下几类别：
- 用户指南：帮助用户入门及使用TQUIC库
- 开发者指南：帮助开发者参入贡献

文档基于[docusaurus](https://docusaurus.io/docs/installation)构建。你可以专注于内容，仅需编写[Markdown](https://guides.github.com/features/Mastering-markdown/)文件即可。

文档编写完成后，你可以使用预览工具查看文档，验证文档在官方网站上能否正确显示。


## 预览工具的使用

### 安装依赖项

请确保操作系统安装了[npm 16.14+](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)。

以Ubuntu系统为例，执行如下命令：

```bash
$ sudo apt-get update && apt-get install -y npm
```

### 下载源代码

首先下载完整的代码库：

```bash
$ git clone https://github.com/tencent/tquic
$ cd tquic/website
$ npm install
```

### 本地运行文档站点

在项目的基目录，执行如下命令：

```bash
$ npm run start -p 8000
...
[SUCCESS] Docusaurus website is running at: http://localhost:8000/
...
```

然后打开浏览器，访问 http://localhost:8000.


## 贡献文档

所有的文档应该使用 [Markdown](https://guides.github.com/features/mastering-markdown/) 格式编写。


### 贡献新的文档

- 英文版本的文档位于目录 `docs/`, 中文版本的文档位于目录 `i18n/zh/docusaurus-plugin-content-docs/current`
- 你可以创建一个新的 `.md` 文件，或者修改已有的文档


### 运行预览工具

- 在项目的基目录，运行预览工具：

```bash
# 查看英文版本
$ npm run start -p 8000

# 查看中文版本
$ npm run start -p 8000 --locale zh
```

- 你也可以将整个站点编译为静态文件，然后使用HTTP服务器提供访问：

```bash
# 静态文件将生成在build目录中
$ npm run build

$ cd build
$ python3 -m http.server 8000
```


### 预览修改的文档

打开浏览器并访问 http://localhost:8000 。

在更新的页面上，单击右上角的“刷新”按钮。



## 发起合入申请

提交修改及发起Pull Request的流程参见[贡献代码](./contribute_codes#guide-of-submitting-pr-to-github)

