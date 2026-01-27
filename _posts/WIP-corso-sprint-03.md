---
layout: post
title: Corso! Sprint 03
tags: [journeys, Corso!]
---

This is the first one on 2026, after vacations with no computer, just enjoying nature, surf and reflecting where I am headed. The sprint 03 goal was make Corso! more reliable for beta usage, we will be covering the progress next.

## Adding a user context

Corso! is live on Azure and one of points that I was not happy is that pretty much anyone could access the vault, even though on Sprint 02 we secured that with Cookie authentication in conjunction with a master password, I'd not like to let it open and anyone can try brute-force the master password. I can leverage features from Azure which are more reliable, one of them is "easy auth", a built-in secure authentication mechanism that does not require any code change, it pretty much add a front-door to your application and only invited users can view it.

![easy auth]({{'assets/images/corso-sprint-03/easy-auth.png' | relative_url}})

I'll not cover details in depth because I believe it is intuitive, there is a well known microsoft documentation how to use it. In summary you can "Add Provider", choose the authentication provider as you prefer, in my case I am using the MS one in combination with Microsoft Entra ID I can even invite external users that are interested at Corso! I did the test with another gmail account.

![corso ms auth]({{'assets/images/corso-sprint-03/corso-ms-auth.png' | relative_url}})

The image has shown 2 accounts that I used but at first try the user is prompted to insert email and password.

## Beta usage

To make it useful somehow, I would need to dump all my registered accounts from 1Password to Corso! I found that it is possible to extract a CSV from there, and all relevant information I need is contained in the file. My decision was to create an upload mechanism tailored for the 1Password CSV file.

Usually, the default decision is using a library that can parse CSV files. It can have so many edge cases in parsing that, in some contexts, it would make sense. However, the philosophy here is to use as little 3rd-party code as possible only in areas where there is an evident security risk I off the work to someone who has already went through the path.

Most of the features we've been building so far were not carrying heavy logic, so manual testing was enough to guarantee correctness. In the case of a parser, it’s a little different. I'll read a CSV string and parse it into some C# POCO using reflection, which adds some spice to the game unit tests will be a smart way to guarantee that I am moving forward correct and in a good pace.

The parser design will take 2 steps: first, Validation, I’ll guarantee this is a valid and parsable CSV file; second, the parse itself. Below is the controller using the parser.

```c#
[HttpPost("import")]
public async Task<ActionResult> Import(IFormFile file)
{  
    if(file is null || file.Length == 0)
    {
        return this.BadRequestProblem("File", $"The file {file?.FileName} was not imported because is empty.");
    }

    using var stream =  file.OpenReadStream();
    var validation = await csvParser.ValidateAsync<Account>(stream, _ => _.Id);
    
    if(validation.Error is not null)
    {
        return this.BadRequestProblem("File", validation.Error.Message);
    }

    var accounts = await csvParser.ParseAsync<Account>(stream, _ => _.Id);
    await vault.UnLockAsync();
    
    foreach(var account in accounts)
    {
        vault.Add(account);
    }

    await vault.LockAsync();
    return Ok();
}
```

I accept a file as input and open the stream that guarantees I'll not exhaust server memory, usually I am dealing with small files which makes things easier and most of them are buffered into memory, but larger files the framework saves it in a temp location, since this multi-part reading that contains boundaries we are able to read in parts without crashing the app. After opening the stream I can delegate the job to the parser, if any error encountered we are returning a bad request though some helper method I wrote to guarantee consistency with Problem details pattern that I've been using so far. 