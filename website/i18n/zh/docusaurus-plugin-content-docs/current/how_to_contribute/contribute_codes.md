---
title: 贡献代码
sidebar_position: 1
---

# 贡献代码

本文目的在于指导你如何在本地开发TQUIC，并将修改提交到官方TQUIC代码库。

## 本地开发指南

本节说明如何在本地环境中开发TQUIC。

### 编码要求

- 请遵守Rust编程语言代码风格规范。
- 所有代码都需要单元测试。所有单元测试都应通过。
- 请参考[代码合入规范](contribute_codes#github-pull-request%E6%8C%87%E5%8D%97)。
  

### [派生代码库](https://help.github.com/articles/fork-a-repo/)

访问Github [TQUIC](https://github.com/tencent/tquic)项目主页，点击`Fork` 按钮生成你个人账号的TQUIC仓库，例如`https://github.com/USERNAME/tquic`


### 克隆代码库

将派生的TQUIC代码库下载到本地：

```bash
$ git clone https://github.com/USERNAME/tquic
$ cd tquic
```

### 创建本地分支

TQUIC项目采用了[Git分支模型](http://nvie.com/posts/a-successful-git-branching-model/)，用于TQUIC的开发、测试、发布和维护。详情请参考[TQUIC分支规范](releasing_process.md).

对于新特性和问题修复，应该从`develop` 分支创建出单独的分支，在新的分支上完成开发。

使用 `git checkout -b` 命令创建并切换到新的分支：

```bash
$ git checkout -b my-cool-stuff
```

需要注意的是，在执行以上命令之前，需要确保当前分支目录是干净的。否则未跟踪的文件会被带入到新的分支中；未跟踪的文件可以通过`git status` 查看。


### 开始开发

例如创建了一个新文件。通过`git status`查看当前状态，它会提示当前目录的修改，你也可以通过`git diff`查看文件的具体修改内容。

```bash
$ git status
On branch test
Untracked files:
  (use "git add <file>..." to include in what will be committed)
	test
no changes added to commit (use "git add" and/or "git commit -a")
```

### 编译及测试

关于编译和测试，请参考[安装](../getting_started/installation)章节。 


### 提交代码

接下来我们提交新增加的测试文件。

```bash
$ git status
On branch test
Untracked files:
  (use "git add <file>..." to include in what will be committed)
	test
nothing added to commit but untracked files present (use "git add" to track)
$ git add test
```

每次Git提交都需要填写提交消息，以便其他开发人员可以了解所做的更改。输入`git commit`：

```bash
$ git commit
[my-cool-stuff c703c041] add test file
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 233
```


### 保持本地仓库更新

在发起Pull Request前，需要与原始代码库(<https://github.com/tencent/tquic>)最新代码保持同步。

使用`git remote`查看当前的远程代码库：

```bash
$ git remote
origin
$ git remote -v
origin	https://github.com/USERNAME/tquic (fetch)
origin	https://github.com/USERNAME/tquic (push)
```

`origin` 是我们下载的远程代码库的名字，即你个人账号下面的TQUIC代码库。接下来我们将原始TQUIC代码库添加为远程代码库并命名为upstream。

```bash
$ git remote add upstream https://github.com/tencent/tquic
$ git remote
origin
upstream
```

获取原始TQUCI代码库最新代码并更新当前分支：

```bash
$ git fetch upstream
$ git pull upstream develop
```

### 推送修改到远程代码库

推送本地修改到Github上，也就是`https://github.com/USERNAME/tquic`

```bash
$ git push origin my-cool-stuff
```


## Github Pull Request指南

在本节，你将了解如何将修改的代码提交到TQUIC官方代码库。


### 创建Issue及合入代码

创建一个Issue来描述问题，并保留其编号。

切换到你创建的分支，并点击`New pull request`

切换到目标分支。Pull Request描述中的`resolve #Issue number`会在Pull Request被合并后自动关闭相应的Issue。更多细节可以在[这里](https://help.github.com/articles/closing-issues-via-commit-messages/)查看。

请等待代码评审。如果需要进一步的代码修改，可以按照上面的步骤更新相应的原始分支。


### 通过单元测试

Pull Request中每一次新的提交都会触发持续集成单元测试，因此请确保在提交消息中包含必要的注释。请参考[commit](contribute_codes.md#%E6%8F%90%E4%BA%A4%E4%BB%A3%E7%A0%81)章节。 

请注意Pull Request中的持续集成单元测试，会执行几分钟才完成。

在完成后，绿色标记表示你的提交已通过所有单元测试。红色标记表示你的提交没有通过全部单元测试。请点击详情查看问题细节并截图，然后将其作为评论添加到Pull Request中。我们会协助进行检查。


### 删除远程分支

当你的Pull Request成功合入主代码库后，你可以在Pull Request页面删除个人远程代码库中的分支。

你也可以使用`git push origin :the_branch_name`命令来删除分支：

```bash
$ git push origin :my-cool-stuff
```

### 删除本地分支

最后，删除本地分支：

```bash
$ git checkout develop # switch to develop branch
$ git branch -D my-cool-stuff # delete my-cool-stuff branch

```

现在我们完成了一次完整的代码贡献过程。


## 关于代码评审的一些规则

为了方便评审人评审代码，请在每次提交代码时遵循以下规则：

(1) 确保持续集成中的单元测试成功通过

如果失败，则意味着在提交的代码中存在问题，代码评审人不会对其进行评审。


(2) 在发起Pull Request前：

- 请注意提交（commit）的数量：
在每次发起Pull Request时尽可能保持提交记录的简洁。你可以使用`git commit --amend`对之前的提交进行补充修改。如果已经向远程仓库推送了多个提交，你可以参考[squash commits after push](http://stackoverflow.com/questions/5667884/how-to-squash-commits-in-git-after-they-have-been-pushed)。

- 请注意提交的的名称：最好表示当前提交的内容，避免太随意。

(3) 如果你已经解决了某个问题，请在Pull Request的**第一条**评论区添加`fix #issue_number`。相应的Issue在Pull Request合并后将自动关闭。关键字包括: close、close、closed、fix、fixes、fixed、resolve、resolves、resolved。请选择合适的词。请参考[Closing issues via commit messages](https://help.github.com/articles/closing-issues-via-commit-messages)了解更多细节。


另外，针对评审人的建议，请遵循以下规定：

(1) 对评审人的每条评论进行回复（这是开源社区的基本礼仪。别人帮了忙，应表达感谢）
   - 如果你采纳了评审人的建议并做了相应的修改，回复一个简单的`Done`更礼貌
   - 如果你没有采纳评审人的建议，请详细说明你的理由

(2) 如果评审意见比较多:
   - 请给出总体的修改情况说明
   - 请参考[开始评审](https://help.github.com/articles/reviewing-proposed-changes-in-a-pull-request/)来发起回复，避免针对每一条评论直接回复，否则每条回复都会导致发送邮件，造成邮件泛滥。


