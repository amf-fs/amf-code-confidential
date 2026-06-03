---
layout: post
title: Open source is not what I thought.
tags: [Journeys, oss-guide]
---

Over the last month, I tried to get a grasp of open source; this is something that I always wished to accomplish but I never found enough energy to start. I say energy because I probably could find 2-4 hours on weekends to try it out, but due to the busy schedule of programming on weekdays (an average 10 hours a day, sometimes including weekends) I preferred to spend free-time in other activities that bring me joy.

## No one is waiting for you

I have been programming since 2010, professionally since 2012. The diversity of experience in the industry made me confident, however I was biased, thinking it would be an easy task, competency in maintain software is not the only skill that matters here, without clear strategy and guidance, it is overwhelming.

My first approach was to find a project related to cybersecurity written in C#, avoiding big code repos due to the complexity and a higher barrier entry, I just wanted one of my PRs merged to get enough confidence and gradually climb to bigger challenges. 

The initial thought sounded appealing and simple, but the result was out of expectation.

## Reality hit me in the face

No one is waiting for my contributions, despite judging myself highly competent in coding. The first challenge slapped me in the face, I had no idea how to find a project that fits the criteria I described before, at this point I am feeling as a rookie.

Googling, which is now chatting with AI (we need a term for this), I got some code repos for potential contribution, for my surprise not many projects related to security written in C# was found, I was looking for something related to Identity/OAuth, at this point nothing appealing to me, IdentityServer 4 would be a good candidate but now it is with a company, at least now is not what I am looking for.

At this point I started to feel frustrated, this not I was expecting and thoughts to just give up started to appear, at the same time, I was interviewing some engineers for Karat dealing with three different contexts: interviewing, open source and consulting was not ideal, making me procrastinate for a while. 

I went a couple of weeks without touching on OSS, same time my timezone was not a good fit for interviews, so it was canceled. It made me to focus back the original plan, exploring even further I found [AspGoat](https://github.com/Soham7-dev/AspGoat){:target="blank" rel="noopener"}. The project was fairly simple and shone like gold, a vulnerable app written using ASP.NET Core related to OWASP, that was exactly what I was looking for.

In my initial research one of the advices I got was to start with small contributions like fixing typos in code and documentation, there is a temptation to write a big chunk of code especially for us that already have relevant experience in coding. This is my first small [PR for AspGoat](https://github.com/Soham7-dev/AspGoat/pull/156){:target="blank" rel="noopener"}, I thought it would be accepted and merged quickly, oh not this time!

Opening the pull request sparked the motivation, and like a kid with a new toy I checked the page for days looking for any feedback, and nothing had happened. It was not high effort but frustrating, I realized that a couple of PRs were stuck waiting for review, so it seems the maintainer has not been active for the last 6 months. Wrong shot!

## Try again

Alright some lessons learned so far, however you never know what you do not know, then I like the approach of "just try this out" then reiterate. I invested minimal effort and started to notice some gaps in my understanding. Now I have a better view of the gaps that I need to close, my first action was trying to find more useful material, or at least someone sharing the OSS experience. Being honest most of advices and materials are repetitive, small summary:

- Learn git basics if you need (in my case I could skip)
- Find a project that you are interested on or has familiarity, maybe something you have been using on your day to day.
- Check the pulse (lesson learned from previous experience) the pulse will tell you how active the project is, you should avoid the stagnated ones.
- Go to issues and filter by labels as such: good first issue
- Send small contributions nothing big

This [tutorial](https://www.youtube.com/watch?v=yzeVMecydCE){:target="blank" rel="noopener"} encompasses most of the stuff above and I found relevant content from freeCodeCamp.

In my second try, I was still focused on finding a project related to security, and I stubbed across Bouncy Castle, I personally never used the library, but I think cryptography is something interesting. I often try to understand how to properly use those algorithms.

No success on finding any good first issue, so I had the idea to fork, clone the repo and look for TODOs inside the code, I personally found out this is a good way to look for work. I found a class called `DerInteger` one of the TODOs was pointing to deprecate some ctors in favor of a static method `ValueOf`, I thought this would be easier to accept and be merged, here is the [contribution](https://github.com/bcgit/bc-csharp/pull/680).

Again, no traction at all!! I started to step away and reflect, I need to educate myself more about the topic, it sounds not so trivial as I was expecting.

## Lessons 

Digging into materials and this time real googling not chatting with AI I found this [OSS guide](https://opensource.guide){:target="_blank" rel="noopener"} the section [how to contribute](https://opensource.guide/how-to-contribute/){:target="blank" rel="noopener"} showed good insights.

After reading the guide and thinking how I was approach I took some valuable lessons to start it again:

- No matter how much experience you have with programming, you will struggle at the beginning as any other skill you want to acquire.
- As any other new skill, consistency is important, define the frequency you think you can get some progress on it and keep trying.
- Avoid contribute with wrong mindset, only seeking PR approvals. 
- Try interact with the community before any contribution.
- Expectation and reality rarely match up and will demand some hard work from you.
- Don't rush be patient
    
This [Podcast](https://www.youtube.com/watch?v=lFyiHwjHPj4&t=64s) was eye opener for me. I was just trying to merge any piece of code no matter where, and than later be able to write this post. It made me rethink the why, I realized this not only about code, merge your PR and post to promote yourself. There is a community behind it and I never tried to interact with them to understand how that people works and their needs, or even if they would be welcome to my contributions.

What I was trying to do in the beginning is considered an anti-pattern working with clients, first we need question the requirements make sure we understand the problem then we write code to solve the right problem, we do not try solve any issue randomly maybe same not even exists, or do not need to be solved. 

Mistakes are part of the process, but I also had my hits, it is important at this point of career develop a internal framework to learn new stuff or even better crack unknown problems. Realize that I take minimum effort go back to the theory and try again, I'll be doing often until figure out stuff.

My next steps will be continuing to watch some podcasts (for this particular topic I found podcasts useful content) and in Parallel exercising the theory. Let's check it out what I get from this approach in the upcoming weeks, thanks for reading it!