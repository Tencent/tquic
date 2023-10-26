---
title: 发布流程
sidebar_position: 3
---

# 发布流程

TQUIC的开发遵循git-flow分支模型，并遵循[语义版本](http://semver.org/)。

## 分支规范

TQUIC开发遵循[git-flow](http://nvie.com/posts/a-successful-git-branching-model/)分支模型, 但针对github进行了微小的调整。

* 对于官方代码库，开发者应遵循[git-flow](http://nvie.com/posts/a-successful-git-branching-model/)。

    * `master`分支是稳定分支。`master`分支的最新提交通过了单元测试和回归测试。

    * `develop`分支是开发分支。`develop`分支的每个提交通过了单元测试，但没有进行回归测试。

    * `release/vX.Y.Z`分支是为发布而创建的临时分支。这个分支上的代码正在进行回归测试。

* 对于复制（forked）的代码库, 开发者不需要严格遵守[git-flow](http://nvie.com/posts/a-successful-git-branching-model/)。复制的代码库中的每个分支等同于feature分支。具体建议如下：

    * 开发者将复制代码库中的`develop`分支与官方代码库保持同步。

    * 开发者从复制代码库中的`develop`分支创建出`feature`分支。

    * 在完成`feature`分支的开发后, 开发者向官方代码库发起 **Pull Request** 以便进行代码评审。

    * 在代码评审过程中，开发者可能继续在`feature`分支上修改和提交代码。

    * 此外，在复制的代码库中也可以创建`bugfix` 分支。与`feature`分支不同的是，开发者应该从`bugfix`分支向官方代码库的多个分支分别发起 **Pull Request** ，包括 `master`分支, `develop`分支，以及可能的 `release/vX.Y.Z`分支。

## 发布流程

发布新版本的操作步骤如下：

1. 从`develop`分支创建一个新分支，分支名称为`release/vX.Y.Z`。例如`release/v0.10.0`。

1. 给新的分支添加标签`X.Y.Z-rcN`(**N**是补丁号)。第一个标签是`0.10.0-rc1`, 第二个标签是`0.10.0-rc2`, 依此类推。

1. 按如下步骤提交新的版本：

    * 修改 **cargo.toml** 文件中的版本信息。

    * 测试版本功能的正确性。如果失败，在`release/vX.Y.Z`分支中修复所有问题，并返回第二步，将补丁号加1。

1. 完成[Release Note](https://github.com/tencent/tquic/blob/develop/CHANGELOG.md)的编写。

1. 将`release/vX.Y.Z`分支合并到`master`分支，删除`release/vX.Y.Z`分支。将`master`分支合并到`develop`分支。

1. 为`master`分支的最新提交添加标签`vX.Y.Z`。


:::note
发布分支一旦创建后，一般不允许从`develop`合入修改到`release/vX.Y.Z`分支中。这确保了`release/vX.Y.Z`分支是冻结的，让QA更容易测试。
:::

:::note
当`release/vX.Y.Z`分支存在时，如果有问题修复，请同时将`bugfix`分支合入到`master`, `develop`and`release/vX.Y.Z`分支。
:::

