---
layout: post
title: Open source is not what I thought.
tags: [Journeys, oss-guide]
---

The last month I tried to get a grasp what open source would looks like, putting myself as a beginner this is something that I always wish todo but I have not found energy to start, and I say energy because I probably could find 2-4 hours on weekends to start, but I was always enough from programming and computers because my full-time positions which would easily take 10 hours a day average, now that I have more control over my working hours sounds good moment to start.

## Is not that easy

I am in programming since 2010, professionally since 2012 up to now due the diverse of experience in the industry that I lived, I was just biased that would be easy to find some project on my interesting and start send contributions, just because I am well competent writing and understanding code, without a clear strategy is too easy to get overwhelmed and that's what happened.

My first approach was finding a project related to cybersecurity written in C#, also avoid big code repos due complexity and bigger barrier entry, I just wanted some of my PR merged to get some confidence and gradually climb to bigger challenges, the initial thought sounded appealing and simple, but the result was out of of expectation.

## The reality on my face

No one is waiting for me start contribute with my years and years of experience writing C# code. First challenge, I had no idea how to find a project that fits those criteria that was my first insight how rookie I am in this topic.

Googling, which is now chatting with AI (we need a term for this), I got some links from code repos, for my surprise not many projects related to security in C# was found, I was looking for something related to Identity, OAuth, the IDS4 was acquired by Duende and I though would be a higher barrier entry other projects did not sound appealing to me.

That phase I started to feel frustration, this not I was expecting and thoughts to just give up started to appear, also same time I was interviewing some engineers for Karat dealing with 3 different contexts: interviewing, open source, consulting was not ideal, possible but since this was new to me started to be exhaustive, then the procrastination started.

Couple weeks without touching on OSS and I stopped interviewing, that leads me to focus back the original plan and this time researching a bit more found a project called [AspGoat](https://github.com/Soham7-dev/AspGoat){:target="blank" rel="noopener"}. The project was fairly simple shined as gold, a vulnerable app written using Asp.Net Core and related to OWASP that I was looking for.

In my initial researches one of advices I got was to start with small contributions like fixing typos on code and documentation, there is a temptation to write a big chunk of code specially for us that already have relevant experience in coding but drawn by corporate jobs. This is first [PR for AspGoat](https://github.com/Soham7-dev/AspGoat/pull/156){:target="blank" rel="noopener"}, small contribution to typos that I though would be accepted and merged quickly, oh not this time!

Opening the pull request sparked the motivation, and like kid with a new toy I checked the page for days looking for any feedback,and nothing had happened. It was not high effort but frustrating, I realized that couple of PRs were stuck waiting for review, so sounds the maintainer is not active for the last 6 months. Wrong shot!

## Try again

Alright some lessons learned so far, however you never know what you do not know, then I like the approach of "just try this out". I had invested minimum effort and started to notice some gaps in my understanding of the open source world. Now I have a better vision what are the gaps that I need to close, my first action was trying to find more useful material some sort of OSS guide, or at least someone which had share some experience. Being honest most of advices and materials are flooded with common advices:

- Learn git basics if you need (in my case I could skip)
- Find a project that you are interested on or has familiarity, maybe something you have been using on your day to day.
- Check the pulse (lesson learned from previous experience) the pulse will tell you how active the project is, you should avoid the stagnated ones.
- Go to issues and filter by labels as such: good first issue
- Send small contributions nothing big

This [tutorial](https://www.youtube.com/watch?v=yzeVMecydCE){:target="blank" rel="noopener"} encompasses most the stuff above and I found relevant content from freeCodeCamp.

In my second try, I was still focused on finding a projects related to security, and I stubbed against bouncy castle, I personally never used the library, but I think crypto something interesting I often try understand how proper use those algorithms.

I had not found any good first issue, so I had the idea to fork, clone the repo and look for TODOs inside the code, I personally found out this is a good way to find for work, and I did. There was class called DerInteger which one of the TODOs was pointing to deprecate some ctors in favor of a static method ValueOf, in this list of TODOs I was looking for something that would not cause any breaking change, I though this would be easier to accept and be merged, here is the [contribution](https://github.com/bcgit/bc-csharp/pull/680).

Again no traction at all!! I started to step way and reflect, I think I need study a bit more about it sounds not so simple as I was thinking, I need find a better approach.







----------TO THE END----------------
Digging into materials and this time real googling not chatting with AI I found this [OSS guide](https://opensource.guide){:target="_blank" rel="noopener"} the web site has different areas tha sound but section (how to contribute)[https://opensource.guide/how-to-contribute/]{:target="blank" rel="noopener"} was very helpful.