---
title: How to contribute codes
sidebar_position: 1
---

# How to contribute codes

The purpose of this document is to guide you through the process of developing TQUIC in a local environment and submitting your changes to the official TQUIC repository.


## Guide of local development

The guidelines in this section will help you develop TQUIC in a local environment.

### Requirements of coding

- Please refer to the coding format of Rust language.
- Unit test is needed for all codes. All unit tests should be passed.
- Please follow [regulations of submitting codes](contribute_codes#guide-of-submitting-pull-request-to-github).
  

### [Fork](https://help.github.com/articles/fork-a-repo/)

Visit the home page of GitHub [TQUIC](https://github.com/tencent/tquic), and then click button `Fork` to generate your own copy of TQUIC, such as <https://github.com/USERNAME/tquic>

### Clone

Clone the forked repository to local:

```bash
$ git clone https://github.com/USERNAME/tquic
$ cd tquic
```

### Create local branch

The [Git stream branch model](http://nvie.com/posts/a-successful-git-branching-model/) is currently applied to TQUIC for the purposes of development, testing, release and maintenance. For more details, please refer to [branch regulation of TQUIC](releasing_process.md).

The development tasks for new features and bug fixes should be completed in a separate branch that branches off from the `develop` branch.

Create and switch to a new branch with the command `git checkout -b`:

```bash
$ git checkout -b my-cool-stuff
```

It is worth noting that before the checkout, it is important to ensure the current branch directory is clean. Otherwise, any untracked files will be brought to the new branch and can be viewed by `git status` .


### Start development

I create a new file in the case. View the current state via `git status`, which will prompt some changes to the current directory, and you can also view the file's specific changes via `git diff` .

```bash
$ git status
On branch test
Untracked files:
  (use "git add <file>..." to include in what will be committed)
	test
no changes added to commit (use "git add" and/or "git commit -a")
```

### Build and test

Please refer to [Installation](../getting_started/installation) about construction and test.


### Commit

Next we submit the new added test file.

```bash
$ git status
On branch test
Untracked files:
  (use "git add <file>..." to include in what will be committed)
	test
nothing added to commit but untracked files present (use "git add" to track)
$ git add test
```

It's required that the commit message is also given on every Git commit, so that other developers can be informed about the changes made. Type `git commit` to realize it.

```bash
$ git commit
[my-cool-stuff c703c041] add test file
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 233
```


### Keep the latest local repository

It needs to keep up with the latest code of the original repository(<https://github.com/tencent/tquic>) before Pull Request.

Check the name of the current remote repository with `git remote`.

```bash
$ git remote
origin
$ git remote -v
origin	https://github.com/USERNAME/tquic (fetch)
origin	https://github.com/USERNAME/tquic (push)
```

`origin` is the name of the remote repository that we clone, which is also the TQUIC under your own account. Next we create a remote of an original TQUIC and name it upstream.

```bash
$ git remote add upstream https://github.com/tencent/tquic
$ git remote
origin
upstream
```

Get the latest code of upstream and update the current branch.

```bash
$ git fetch upstream
$ git pull upstream develop
```

### Push to remote repository

Push local modification to GitHub(`https://github.com/USERNAME/tquic`).

```bash
$ git push origin my-cool-stuff
```


## Guide of submitting Pull Request to GitHub

You will learn how to contribute your changes to the official repository of TQUIC following the guidelines provided in this section.


### Create an Issue and finish Pull Request

Create an Issue to describe your problem and keep its number.

Switch to the branch you have created and click `New pull request`.

Switch to the targeted branch. A note of `resolve #Issue number` in Pull Request description results in automatic close of corresponding Issue after the merge of PR. More details can be viewed [here](https://help.github.com/articles/closing-issues-via-commit-messages/).

Please wait for the review. If any modifications are necessary, you can update the corresponding branch in origin by following the steps above.


### Pass unit tests

Every new commit in your Pull Request will trigger CI unit tests, so please ensure that necessary comments have been included in your commit message. Please refer to [commit](contribute_codes.md#commit).

Please note the procedure of CI unit tests in your Pull Request which will be finished in several minutes.

Green ticks after all tests means that your commit has passed all unit tests. Red cross after the tests means your commit hasn't passed certain unit test. Please click detail to view bug details and make a screenshot of the bug, then add it as a comment in your Pull Request. Our stuff will help you check it.

### Delete remote branch

We can delete branches of remote repository in Pull Request page after your Pull Request is successfully merged into master repository.

We can also delete the branch of remote repository with `git push origin :the_branch_name`:

```bash
$ git push origin :my-cool-stuff
```

### Delete local branch

Finally, we delete the local branch

```bash
$ git checkout develop # switch to develop branch
$ git branch -D my-cool-stuff # delete my-cool-stuff branch

```

And now we finish a full process of code contribution


## Certain regulations about code review

In order that reviewers focus on code in the code review, please follow these rules every time you submit your code:

(1) Make sure that unit tests in Travis-CI pass through successfully.

If it fails, it means problems have been found in submitted code which will not be reviewed by reviewers.

(2) Before the submit of Pull Request:

- Please note the number of commits:
Keep commit concise as much as possible at every submit. You can make a supplement to the previous commit with `git commit --amend`. About several commits having been pushed to remote repository, you can refer to [squash commits after push](http://stackoverflow.com/questions/5667884/how-to-squash-commits-in-git-after-they-have-been-pushed)。

- Pay attention to the name of every commit: It would be better to abstract the content of the present commit and be not too arbitrary.

(3) If you have tackled with problems of an Issue, please add `fix #issue_number` to the * *first* comment area of Pull Request. Then the corresponding Issue will be closed automatically after the merge of Pull Request. Keywords are including: close, closes, closed, fix, fixes, fixed, resolve, resolves, resolved. Please select an appropriate word. Please refer to [Closing issues via commit messages](https://help.github.com/articles/closing-issues-via-commit-messages) for more details.

In addition, please follow the following regulations in response to the suggestion of reviewers:

(1) A reply to every comment of reviewers（It's a fundamental complimentary conduct in open source community. An expression of appreciation is a need for help from others):
   - If you adopt the suggestion of reviewer and make a modification accordingly, it's courteous to reply with a simple `Done` .
   - Please clarify your reason for the disagreenment

(2) If there are many suggestions
   - Please show general modification
   - Please follow [start a review](https://help.github.com/articles/reviewing-proposed-changes-in-a-pull-request/) to give your reply, instead of directly replying for that every comment will result in sending an email causing email disaster.


