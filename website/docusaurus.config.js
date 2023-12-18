// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'TQUIC',
  tagline: 'High performance, lightweight and cross-platform QUIC library',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://tquic.net',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'tencent', // Usually your GitHub org/user name.
  projectName: 'tquic', // Usually your repo name.

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en', 'zh'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/tencent/tquic-website/tree/main/packages/create-docusaurus/templates/shared/',
	  showLastUpdateTime: true,
	  showLastUpdateAuthor: true,
        },
        blog: {
          showReadingTime: true,
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/tencent/tquic-website/tree/main/packages/create-docusaurus/templates/shared/',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  scripts: [
    // Access Statistics
    {
      src: 'https://hm.baidu.com/hm.js?5f7e9bd63c8f9a814fb73b9ff8c2235b',
      async: true,
    },
  ],

  themes: [
    [
      require.resolve("@easyops-cn/docusaurus-search-local"),
      /** @type {import("@easyops-cn/docusaurus-search-local").PluginOptions} */
      ({
        // `hashed` is recommended as long-term-cache of index file is possible.
        hashed: true,
        // For Docs using Chinese, The `language` is recommended to set to:
        language: ["en", "zh"],
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      image: 'img/docusaurus-social-card.jpg',
      navbar: {
        title: 'TQUIC',
        logo: {
          alt: 'TQUIC Logo',
          src: 'img/logo.png',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'left',
            label: 'Docs',
          },
          {to: '/blog', label: 'Blog', position: 'left'},
	  {
            type: 'localeDropdown',
            position: 'right',
          },
          {
            href: 'https://github.com/tencent/tquic',
            position: 'right',
            className: 'header-github-link',
           'aria-label': 'GitHub repository',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: 'Getting Started',
                to: 'docs/category/getting-started',
              },
              {
                label: 'FAQ',
                to: 'docs/category/frequently-asked-questions',
              },
            ],
          },
          {
            title: 'Project',
            items: [
              {
                label: 'Use cases',
                href: 'https://github.com/tencent/tquic/blob/develop/ADOPTERS.md',
              },
              {
                label: 'Roadmap',
                href: 'https://github.com/tencent/tquic/milestones',
              },
              {
                label: 'Issues',
                href: 'https://github.com/tencent/tquic/issues',
              },
              {
                label: 'Releases',
                href: 'https://github.com/tencent/tquic/releases',
              },
              {
                label: 'Contributing',
                to: '/docs/category/contributing',
              },
            ],
          },
          {
            title: 'Community',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/Tencent/tquic/discussions',
              },
              {
                label: 'Stack Overflow',
                href: 'https://stackoverflow.com/questions/tagged/tquic',
              },
              {
                label: 'Discord',
                href: 'https://discord.com/invite/bXChN5DE2h',
              },
            ],
          },
          {
            title: 'Social',
            items: [
              {
                label: 'Blog',
                to: '/blog',
              },
              {
                label: 'Twitter',
                href: 'https://twitter.com/tquic_project',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} The TQUIC Authors | Documentation Distributed under CC-BY-4.0 <br> Copyright © ${new Date().getFullYear()} Tencent. All Rights Reserved. <a href=https://beian.miit.gov.cn style="color:#FFFFFF;">GD B2-20090059-1892</a>`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
      },
    }),
};

module.exports = config;
