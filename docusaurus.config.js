// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config

import { themes as prismThemes } from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
    title: 'TryHackMe CN Mirror',
    tagline: 'With GPT，我们可以实现更贴合中文的 Tryhackme 学习体验',
    favicon: 'img/favicon.ico',

    // Set the production url of your site here
    url: 'https://tryhackmyoffsecbox.github.io/',
    // Set the /<baseUrl>/ pathname under which your site is served
    // For GitHub pages deployment, it is often '/<projectName>/'
    baseUrl: '/TryHackMe-CN/',

    // GitHub pages deployment config.
    // If you aren't using GitHub pages, you don't need these.
    organizationName: 'TryHackMyOffsecBox', // Usually your GitHub org/user name.
    projectName: 'TryHackMe-CN', // Usually your repo name.

    onBrokenLinks: 'throw',
    onBrokenMarkdownLinks: 'warn',

    // Even if you don't use internationalization, you can use this field to set
    // useful metadata like html lang. For example, if your site is Chinese, you
    // may want to replace "en" with "zh-Hans".
    i18n: {
        defaultLocale: 'zh-Hans',
        locales: ['zh-Hans'],
    },

    presets: [
        [
            'classic',
            /** @type {import('@docusaurus/preset-classic').Options} */
            ({
                docs: {
                    sidebarPath: './sidebars.js',
                    // Please change this to your repo.
                    // Remove this to remove the "edit this page" links.
                    editUrl:
                        'https://github.com/CTF-Archives/Tryhackme-CN/edit/main/',
                },
                blog: {
                    showReadingTime: true,
                    // Please change this to your repo.
                    // Remove this to remove the "edit this page" links.
                    editUrl:
                        'https://github.com/CTF-Archives/Tryhackme-CN/edit/main/',
                },
                theme: {
                    customCss: './src/css/custom.css',
                },
            }),
        ],
    ],

    themeConfig:
        /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
        ({
            // Replace with your project's social card
            image: 'img/docusaurus-social-card.jpg',
            navbar: {
                title: 'Tryhackme CN Mirror',
                logo: {
                    alt: 'My Site Logo',
                    src: 'img/logo.svg',
                },
                items: [
                    {
                        type: 'docSidebar',
                        sidebarId: 'LearningPaths_Sidebar',
                        position: 'left',
                        label: 'Learning Paths',
                    },
                    {
                        type: 'docSidebar',
                        sidebarId: 'Modules_Sidebar',
                        position: 'left',
                        label: 'Modules',
                    },
                    {
                        type: 'docSidebar',
                        sidebarId: 'Networks_Sidebar',
                        position: 'left',
                        label: 'Networks',
                    },
                    { to: '/blog', label: 'Blog', position: 'left' },
                ],
            },
            footer: {
                style: 'dark',
                copyright: `Copyright © ${new Date().getFullYear()} Tryhackme CN Mirror Built with Docusaurus.`,
            },
            prism: {
                additionalLanguages: ['powershell', 'php', 'ini', 'json', "aspnet"],
                theme: prismThemes.github,
                darkTheme: prismThemes.dracula,
            },
            docs: {
                sidebar: {
                    autoCollapseCategories: true,
                },
            },
        }),
};

export default config;
