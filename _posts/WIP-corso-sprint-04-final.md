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

**Disaster** it did lot's of modifications to the web project and in the end it even broke the build, I did another prompt telling to fix build issues without much guidance about the problems, at least it could fix. I tried to test the app, without any code review yet and it was so bad, all the features were broken, also it added custom css classes that caused horrendous user experience, not sure if there is a more appropriate model for it, but this is terrible for UI look and feel in general it needs the human input.

You threat the agent as a jr engineer, you cannot throw a problem you will need to help breaking down in small activities that you are able to track the progress, and most important if this is headed to the right direction.

## Let's give another try

Despite the first experience has not produced good outcomes, it served as a kind of prototype, reviewing all code changes I had a better idea about the areas I would need to touch and then I started to reflect how I usually approach when I am doing a manual refactoring. I am a huge advocate of small verifiable changes, so I started break into some small tasks to achieve the design I would like. Below I'll start paste the prompts I used in italic and right after comment the outcomes, expect some typos and grammar mistakes.

*Let's move the new account button to a action bar to the top and when clicked we will open a dialog with the account form, save and cancel options, so it will allow us create new accounts.*

The one above has not produced good results, it did not take into consideration the libraries the project already contains such as Tailwind and Angular Material, so many unnecessary code was created, also the file names were poor not following the project conventions, changes that I have not asked for were introduced. I had to undo all changes, and now I have to be more specific.

*Let's move the new account button to action bar to the top of the account component, the dialog I want it named as account-dialog.component, avoid create your own css the project already contains tailwind to help. The dialog should contain all account form logic, with fields, cancel and save buttons. Keep changes minimal*

Now we made a good progress, however I had to prompt a little more for fixing compilation issues and remove changes I haven't asked for (this is the proactive jr. dev).

*Now we will do similar task but with import csv feature, move the button to the action bar, and preserve the feature as is, the button has dual function choose a file and then later upload it keep that, I just want refactor the content disposition.*

For my surprise things are getting better, now I had not to ask to fix compilation issues it seems the agent is learning, this is running *npm build* to check errors auto fixing them. Little back and forth because it forgot to move the delete button to unload the loaded file, and had introduced few bugs. The tool leave behind lot's of zombie unused code, then I had to ask to start clean up the things a little bit.

At this point I started to develop some framework to work with it: 

1. Create the prompt 
2. Test 
3. Review the code 
4. Refactor 
5. Test again.

*Now we will add the edit feature, on the accoun-list instead of radio selection we will add an icon to edit and reuse the account-dialog, passing the accounts values to it, the tile should change dinamic like "Editing {{account.title}}", and the save should call the update method if account is provided, do not forget this is mobile friendly then if account title is too big we may need to truncate and add an elipsys to prevent overlapping* 

The feature was kept intact but the UI was looking terrible it did not remove the selection button and replaced by edit icon, moreover we had overlapping issues between them. Couple more prompts and I could handle it, one thing to emphasize is that sometimes I still need to remember the tool to rely on libraries like Angular Material instead of building from scratch.

*Now that we created the action bar at the top and transferred all account form features to the account model, we fully delete the account-form component and references pay attention to build issues and dead code.*

Somehow it broke the dialog that was previously working despite I haven't mentioned anything related it did couple changes there, I did the analysis myself and point the issue to let it fix.

*somehow you broke the dialog feature when I hit save is not passing proper account, to the api calls to POST and PUT*

That one worked well and the bug was fixed.

The tool has terrible sense of architecture and how to organize the code, at the end of this activity I had something working already quite surprising for a morning, not sure if I could achieve the same without it. So my last prompts were about refactoring the whole architecture into smaller more concise files.

*there where I am highligthing, is the action bar, let's create a component for that called action-bar and let's sticky to the top when I am scrolling the list.* (back and forth here bugs with sticky to the top I end-up fixing manually)

*all file handling should be transfered to action-bar, and maybe use output event when file is uploaded so it can refresh account list, same strategy when new account created*

*for new account same strategy open dialog on action bar and raise an even only if new account created so account list can be refreshed* (some reason was adding white background to the action bar, who knows...)

I had some struggle with the tool, because what sounds obvious to you can be totally analogous to the agent, but it was a good achievement for a whole morning, it definitely boost my outcome. 

## My humble opinion

If you are at least one decade in the tech industry you probably had seen the "Hype" a couple of times already, for the ones new to it here is how it works. It starts with some sort of innovation that cause real impact in how we deal software, second it get's exaggerated in a insane level that people think they discover the silver bullet, despite many advices and we know our work is mostly to deal with trade-offs, since they think is possible to use the new tool, solution or practice everywhere things start to go bad which I believe it is ok this would be a phase that we are discovering the real use cases and the limitations of this innovation, the limit always exist, lastly companies start to pay the price of abusing the technology and trying to fit on everything, some assume the losses and change direction, other group has the dumb ego inflated not assuming the reality and go bankruptcy. Examples of similar hypes were Blockchain, TDD, No-Code, Agile, Microservices...

What this time surprised was the brutal marketing on AI tools and the fear created on people for loosing their jobs, it was so intense that naive VP's, Managers started to truly believe this could replace a engineer and we see now most Big Techs hiring the work force back, such a shame. I felt that it was a big lie and I just wait the hype come to me, yes I did not take any proactive action to go deeper into those tools because I knew this would stumble my door and I would need to catch up at least the basics that's what I call "paid learning", I remember being more interest and still true in cybersecurity than this tool. I did a quick look and realize ok this can help now I do not need my code generators anymore nor my bash scripts to refactor big code bases, but that's it you know, all decent engineers in some point were trying to generate code automatically because we were just tired of keeping writing same CRUD, login API again again, so we could focus where the real challenge was or up skill somewhere. 

We are now in the last phase everyone is noticing there is a buble, no AGI will come and trillions were spent to build that without proper ROI.

The tool boost the productivity no doubt about it, I do not want go back when I had to click on many links on Google to get an answer, but this needs to be treated as a "dumb intern" there is no way this will replace me, it can barely solve well-known problems without assistance and constant reviews, the quality / security still horrendous, which makes an awesome tool in the right hands, a true Sr. level engineer who knows the problem to be solved and is able to fix poor outcomes produced, it's an incredible tool for bootstrapping new code bases and big refactorings, however it make bad engineers extremely louder, which makes easy to identify them, recently I've being denying several pull request once I get back saying *"Hey at least did you review this code, before asking for?"* the default answer has been *"Ow, I did but this part was AI generated"*, you see now those people has excuse for their buggy crap work.

Be mindfulness, it is easy to get addicted to the tool and start loosing your skill, I am making sure I use it in controlled manner, I never delegate 100% to the tool, making sure there are parts of the code that I still write by myself, this coming into a equation that my activity is even more enjoyable. My advice for the beginners avoid generate code with it as much as you can, there is no way for you to learn anything if you are not practicing, however this is now a huge ally to grasp more complex context in CS word, I've been leveraging it a lot.

The message in the end is [don't give up your brain](https://cassidoo.co/post/good-brain/?ref=dailydev).

## Corso! Will have a break

I have been using Corso! activelly in my day to day and I am pretty satisfied with it, soon I can cancel my 1password subscription, I just need to finish minor adjustments like backup files and so on since this is a sensitive data that I cannot loose at any cost.

I decided take a break after this first Release to focus in diferent projects in this 12 years in the industry I came to realize that I've never contributed to open-source, often way too busy with full-time jobs, that I've never found energy to do. 

My goal now towards end of this year is embracing open source at least give some contributions learn the process how to get into it, and off course document the experience, hope will help, thanks for reading it!



