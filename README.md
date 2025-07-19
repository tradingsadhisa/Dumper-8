#Dumper 8Downloads| |Downloads_month| |PyPI version| |GitHub contributors|

.. |Downloads| image:: https://pepy.tech/badge/twitterscraper
   :target: https://pepy.tech/project/twitterscraper
.. |Downloads_month| image:: https://pepy.tech/badge/twitterscraper/month
   :target: https://pepy.tech/project/twitterscraper/month
.. |PyPI version| image:: https://badge.fury.io/py/twitterscraper.svg
   :target: https://badge.fury.io/py/twitterscraper
.. |GitHub contributors| image:: https://img.shields.io/github/contributors/taspinar/twitterscraper.svg
   :target: https://github.com/taspinar/twitterscraper/graphs/contributors


Backers
========

Thank you to all our backers! 🙏 [`Become a backer`_]

Sponsors
========

Support this project by becoming a sponsor. Your logo will show up here
with a link to your website. [`Become a sponsor`_]

.. _Become a backer: https://opencollective.com/twitterscraper#backer
.. _Become a sponsor: https://opencollective.com/twitterscraper#sponsor


Synopsis
========

A simple script to scrape Tweets using the Python package ``requests``
to retrieve the content and ``Beautifulsoup4`` to parse the retrieved
content.

1. Motivation
=============

Twitter has provided `REST
API's <https://dev.twitter.com/rest/public>`__ which can be used by
developers to access and read Twitter data. They have also provided a
`Streaming API <https://dev.twitter.com/streaming/overview>`__ which can
be used to access Twitter Data in real-time.

Most of the software written to access Twitter data provide a library
which functions as a wrapper around Twitter's Search and Streaming API's
and are therefore constrained by the limitations of the API's.

With Twitter's Search API you can only send 180 Requests every 15
minutes. With a maximum number of 100 tweets per Request, you
can mine 72 tweets per hour (4 x 180 x 100 =72) . By using
TwitterScraper you are not limited by this number but by your internet
speed/bandwith and the number of instances of TwitterScraper you are
willing to start.

One of the bigger disadvantages of the Search API is that you can only
access Tweets written in the **past 7 days**. This is a major bottleneck
for anyone looking for older data. With TwitterScraper there is no such 
limitation.

Per Tweet it scrapes the following information:
 + Tweet-id
 + Tweet-url
 + Tweet text
 + Tweet html
 + Links inside Tweet
 + Hashtags inside Tweet
 + Image URLS inside Tweet
 + Video URL inside Tweet
 + Tweet timestamp
 + Tweet Epoch timestamp
 + Tweet No. of likes
 + Tweet No. of replies
 + Tweet No. of retweets
 + Username
 + User Full Name / Screen Name
 + User ID
 + Tweet is an reply to
 + Tweet is replied to
 + List of users Tweet is an reply to
 + Tweet ID of parent tweet

 
In addition it can scrape for the following user information:
 + Date user joined
 + User location (if filled in)
 + User blog (if filled in)
 + User No. of tweets
 + User No. of following
 + User No. of followers
 + User No. of likes
 + User No. of lists
 + User is verified


2. Installation and Usage
=========================
Just a fork of dumper 7 to make it easier to use dumper 7 for fortnite generation.
https://www.instagram.com/shehara.mkarunaratne?igsh=cG9ubnpkOHZha3B3