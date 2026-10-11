# Phase 1 scope spot-check (2026-10-10)

Bounded product-role review. Selection: up to two CVEs per rule ordered by SHA-256(CVE ID).
Descriptions and positive vulnerable CPEs were inspected alongside the official product-role sources.
Not a random accuracy estimate, not independent human review, and not proof of all deployment applicability.

| Product | CVE inspected | Role evidence |
|---|---|---|
| wordpress:wordpress | CVE-2023-2745 | [Web CMS core](https://wordpress.org/about/) |
| wordpress:wordpress | CVE-2023-38000 | [Web CMS core](https://wordpress.org/about/) |
| drupal:drupal | CVE-2022-25278 | [Web CMS core](https://www.drupal.org/about) |
| drupal:drupal | CVE-2024-45440 | [Web CMS core](https://www.drupal.org/about) |
| joomla:joomla! | CVE-2024-26279 | [Web CMS core](https://www.joomla.org/about-joomla.html) |
| joomla:joomla! | CVE-2023-23750 | [Web CMS core](https://www.joomla.org/about-joomla.html) |
| djangoproject:django | CVE-2024-24680 | [Web framework](https://www.djangoproject.com/) |
| djangoproject:django | CVE-2024-39330 | [Web framework](https://www.djangoproject.com/) |
| apache:tomcat | CVE-2024-21733 | [Servlet Web application server](https://tomcat.apache.org/) |
| apache:tomcat | CVE-2023-41080 | [Servlet Web application server](https://tomcat.apache.org/) |
| apache:http_server | CVE-2024-39884 | [HTTP server](https://httpd.apache.org/) |
| apache:http_server | CVE-2022-36760 | [HTTP server](https://httpd.apache.org/) |
| vmware:spring_framework | CVE-2023-20861 | [Application framework with Web support](https://spring.io/projects/spring-framework/) |
| vmware:spring_framework | CVE-2023-20863 | [Application framework with Web support](https://spring.io/projects/spring-framework/) |
| laravel:framework | CVE-2022-40482 | [Web application framework](https://laravel.com/) |
| laravel:framework | CVE-2024-52301 | [Web application framework](https://laravel.com/) |
| rubyonrails:rails | CVE-2024-26143 | [Web application framework](https://rubyonrails.org/) |
| rubyonrails:rails | CVE-2023-22795 | [Web application framework](https://rubyonrails.org/) |
| discourse:discourse | CVE-2024-36113 | [Web discussion application](https://www.discourse.org/) |
| discourse:discourse | CVE-2024-52589 | [Web discussion application](https://www.discourse.org/) |
| moodle:moodle | CVE-2024-33997 | [Web learning platform](https://moodle.org/) |
| moodle:moodle | CVE-2021-36399 | [Web learning platform](https://moodle.org/) |
| nextcloud:nextcloud_server | CVE-2024-52518 | [Web file sharing server; not desktop client](https://nextcloud.com/files/) |
| nextcloud:nextcloud_server | CVE-2023-28643 | [Web file sharing server; not desktop client](https://nextcloud.com/files/) |
| facebook:hermes | CVE-2023-24832 | [JavaScript engine used by React Native; applicability remains conditional](https://reactnative.dev/docs/hermes) |
| facebook:hermes | CVE-2023-23556 | [JavaScript engine used by React Native; applicability remains conditional](https://reactnative.dev/docs/hermes) |
| patreon:flutter_downloader | CVE-2023-41387 | [Flutter Android/iOS downloader plugin](https://pub.dev/packages/flutter_downloader) |

Exclusion/pending checks: desktop Chrome CVE-2022-3863; Android/EMUI service CVEs 2022-39104, 2022-44423, 2022-44439, 2022-47976; general multimedia library CVE-2022-46489.
Other N2 excluded examples include kernel driver CVE-2022-39118 and desktop agent CVE-2022-43533. These are recorded in the annotation transfer; unmatched products stay needs_review.

Mobile caution: Hermes evidence identifies a runtime used by React Native; most apps are not affected unless untrusted JavaScript is executed under the advisory conditions. flutter_downloader concerns a mobile plugin directly.
Spring is classified by its framework role; this does not claim every deployment exposes the vulnerable expression evaluator to the Internet.
