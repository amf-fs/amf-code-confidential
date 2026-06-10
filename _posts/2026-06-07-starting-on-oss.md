---
layout: post
title: Open source is not what I thought.
tags: [journeys, oss-guide]
---

Over the last month I tried to get a grasp of open source. It's something I've always wished to accomplish, but I never found enough energy to start. By "energy" I mean 2-4 hours during the weekends to try it out, but due to the busy schedule of programming on weekdays (an average of 10 hours a day, sometimes including weekends) I always chose to spend my free time on other activities that bring me joy.

## No one is waiting for you

I have been programming since 2010, professionally since 2012. The diversity of experience in the industry made me confident, however I was biased: I thought OSS would be easy to start. Competency in maintaining software is not the only skill that matters here, without clear strategy and guidance, it becomes overwhelming.

My first approach was to find a project related to cybersecurity written in C#, avoiding big code repos due to the complexity and a higher barrier entry, I just wanted one of my PRs merged to get enough confidence and gradually climb to bigger challenges. 

The initial thought sounded appealing and simple, but the result was out of expectation.

## The reality

Although judging myself highly competent in coding, the first challenge slapped me in the face: I had no idea how to find a project that fits my criteria.

Googling around, I got some repos for potential contribution. To my surprise, there weren't many security C# projects. I was looking for something related to Identity/OAuth; IdentityServer 4 could've been a good candidate, but now it is maintained by a company not what I wanted.

I was stuck and tempted to give up, in parallel I was interviewing some engineers for Karat, dealing with three different contexts: interviewing, open source and consulting was not ideal, making me procrastinate for a while. 

I went a couple of weeks without touching on OSS. My timezone was not a good fit for interviews, so some were canceled which made me focus on the original plan. 

Exploring even further I found [AspGoat](https://github.com/Soham7-dev/AspGoat){:target="blank" rel="noopener"}, the project was fairly simple and shone like gold; a vulnerable app in ASP.NET Core focused on OWASP. That was exactly what I was looking for.

In my initial research one of the advices I got was to start with small contributions: fixing typos and documentation. There is a temptation to write a big chunk of code especially for us that already have relevant experience in coding. This is my first small [PR for AspGoat](https://github.com/Soham7-dev/AspGoat/pull/156){:target="blank" rel="noopener"}, I thought it would be accepted and merged quickly (not this time!).

Opening the PR reignited the motivation, like a kid with a new toy, I checked the page for days, looking for feedback, and nothing happened. I realized that a couple of PRs were stuck waiting for review, so it seems the maintainer has not been active for the last six months. Wrong shot!

## Try again

Alright some lessons learned so far, however you never know what you don't know. I like the approach "just try and iterate". I noticed some gaps in my understanding, now I have a better view on what I need to work on. 

My first action was to look for useful material, or someone sharing OSS experience. To be honest most of advices are repetitive. Here is a small summary:

- Learn git basics if you need to (in my case I could skip)
- Pick a project you are familiar with.
- Avoid stagnant repos, always check the pulse.
- Go to issues and filter by labels like "good first issue"
- Small PRs first.

This [tutorial](https://www.youtube.com/watch?v=yzeVMecydCE){:target="blank" rel="noopener"} covers most of the stuff above. It's a relevant content from freeCodeCamp.

On my second try I stubbed across Bouncy Castle. I hadn't used the library before, but cryptography calls my attention, I naturally find myself digging into details of it.

No success on finding any "good first issue", so I had the idea to fork the repo looking for "TODOs" on source code, by the way this is a smart strategy to begin with. I found a class called `DerInteger` one of the "TODOs" was pointing to deprecate some ctors in favor of a static method `ValueOf`, I thought this would be easier to accept and be merged, here is the [contribution](https://github.com/bcgit/bc-csharp/pull/680){:target="blank" rel="noopener"}.

Again; no traction.

## Lessons 

Googling again led me to the [OSS guide](https://opensource.guide){:target="_blank" rel="noopener"} the section [how to contribute](https://opensource.guide/how-to-contribute/){:target="blank" rel="noopener"} offered me good insights.

From the guide and previous experience, I learned:

- No matter your experience, struggling is part of the process.
- Consistency is important, keep a sustainable pace.
- Avoid to contribute only seeking PR approvals. 
- Try to interact with the community.
- Expectation and reality rarely matches, it will demand some hard work.
- Don't rush; be patient.
    
This [Podcast](https://www.youtube.com/watch?v=lFyiHwjHPj4&t=64s) was eye opener for me. I was trying to merge any piece of code no matter where, to write a post later. It made me to rethink the why of all it. There is a community behind it and I never tried to interact with them to understand how that people works and their needs, or even if they'd welcome my contributions.

I'd avoid this approach at any cost when working with my clients: first question the requirements make sure proper understanding of the problem then write the code solving the right problem. 

Mistakes are part of the process, but I also had my hits. It's important at this point of career develop a internal framework to learn new stuff or even better crack unknown problems. Note that I take minimal effort, revisit the theory then try again. I'll repeat this over and over.

My next steps will be continuing to watch some podcasts (for this particular topic I noticed podcasts are useful content). Let's check it out what I can get in the upcoming weeks. Thanks for reading it!