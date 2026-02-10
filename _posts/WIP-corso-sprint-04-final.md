---
layout: post
title: Corso! Sprint 04 - Final Release
tags: [journeys, Corso!]
---

Last sprint we focused on app reliability after my beta usage and testing I started realize the UI on mobile was just shit! Since I am using AI tooling quite often in daily work I would like to take opportunity to vibe code with [copilot ](https://copilot.microsoft.com/). I'll give an overview how the process was and my honest opinion about the tool, I am using [Claude Haiku 4.5](https://www.anthropic.com/news/claude-haiku-4-5) as a model.

## My dump intern

I knew that make an UI mobile friendly would be a good problem for AI to solve, because it has plenty of material over the wire about guidelines design consideration and so on...

At beginning I did not find this is a big problem to solve it should be relatively easy the code is already using Tailwind + Angular material we just need to change the user experience a bit instead of using everything in a single page, would need to split the workflow a little bit. I started to give some prompts to copilot explaining the issue the user was facing in mobile and what are the options available, this I call the brainstorming phase good to bring some context I feel the tool start take more assertive decisions, I am using the agent mode to avoid any code change at this step I need to specify that we will brainstorm some solution before editing any file. It gave me four options: Vertical stack, modal dialog pattern, tabs / accordions pattern, drawer sidebar pattern. I choose the modal dialog pattern that would be a grace fit, all other options were considering inserting a break point to detect smaller screens and then transform the UI, I would not like to maintain two versions of it, with dialogs we can tackle mobile and desktop with a unified experience.

After confirming the approach we would take, I asked the agent to execute the task and then...

**Disaster** it did lot's of modifications to the web project and in the end it even broke the build, I did another prompt telling to fix build issues without tha much explanation about the issues, at least it could fix. I did not start reviewing the code, I tried to test the app and it was so bad all the features were broken also it added custom css classes that caused horrendous user experience, not sure if there is a more appropriate model for it, but this is terrible for UI look and feel in general it needs the human input here. 