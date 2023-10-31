---
title: How to contribute documents
sidebar_position: 2
---

# How to contribute documents

TQUIC's documentation is mainly divided into the following categories:
- User Guide: to help users get started and use the library
- Developer Guides: to meet the needs of TQUIC developers

Our documentation is built with [docusaurus](https://docusaurus.io/docs/installation). It enables you to focus on your content and just write [Markdown](https://guides.github.com/features/Mastering-markdown/) files.

Once the document is written, you can use the preview tool to check how the document appears to verify that your document is displayed correctly on the official website.


## How to use the preview tool

### Install its dependencies

Before doing this, please make sure your operating system has [npm 16.14+](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) installed.

Take the ubuntu system as an example, run:

```bash
$ sudo apt-get update && apt-get install -y npm
```

### Clone related repository

First download the full repository:

```bash
$ git clone https://github.com/tencent/tquic
$ cd tquic/website
$ npm install
```

### Run document site locally

Execute the following command under the base directory of the project:

```bash
$ npm run start -p 8000
...
[SUCCESS] Docusaurus website is running at: http://localhost:8000/
...
```

Then open your browser and navigate to http://localhost:8000.


## Contribute documents

All content should be written in [Markdown](https://guides.github.com/features/mastering-markdown/) .


### Contribute new documents

- The English version of documents can be found in the `docs/` directory, while the Chinese version are located in the `i18n/zh/docusaurus-plugin-content-docs/current` directory
- Create a new `.md` file or modify an existing file in the repository you are currently working on


### Run the preview tool

- Run the preview tool in the base directory of the project:

```bash
# Preview the English version
$ npm run start -p 8000

# Or preview the Chinese version
$ npm run start -p 8000 --locale zh
```

- You can also build the whole website into static files and host them using an HTTP server: 

```bash
# The static files will be generated within the build directory.
$ npm run build

$ cd build
$ python3 -m http.server 8000
```


### Preview modification

Open your browser and navigate to http://localhost:8000 .

On the page to be updated, click Refresh Content in the top right corner.



## Pull Request for your changes

The process of submitting changes and PR can be found in [How to contribute code](./contribute_codes#guide-of-submitting-pr-to-github)

