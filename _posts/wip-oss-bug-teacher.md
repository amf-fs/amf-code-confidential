---
layout: post
title: A bug, the best teacher
tags: [journeys, oss-guide]
---

Continuing my journey on Oss, I switched to a more relevant project in .NET ecosystem. Here we will explore my latest PR fixing a bug in a web server, despite it was trivial lines of code it forced me explore further concepts about the HTTP protocol. In this post we will dig into hacking, HPACK tables, http trailers and the mindset I use to face bug.

## Switching focus

Past months I was little overwhelmed about some of my contributions not getting some feedback, so I decided to contribute to ASP.NET Core because I would know the repo would have a good pulse and active maintainers. The codebase was huge, best strategy was focusing in some particular area of the project. If you are following one of my areas of interesting is security, and I sent a small contribution to a crypto library realizing that was way too specific knowledge, I prefer act on something that I can combine different aspects and deliver something useful, a web server such as Kestrel would be a sweet spot. Checking the list of open issues I found this [bug](https://github.com/dotnet/aspnetcore/issues/68371){:target="blank" rel="noopener"}, this a good place to start.

## A man is not an island

Trying to avoid past mistakes, avoiding pulling my head down to the keyboard, my first attitude was making sure I understood what is in the ticket and confirming my approach with the maintainer, having these healthy small interactions are the best way to get involved in the community. 

My first approach was cloning the repo trying to build and execute tests, there are good material on README files, how to do it, since framework is huge is counter-productive load all modules from root, so I could setup at least the Kestrel part getting the test up and running.

After it I did a small analysis, and confirmed my approach with the maintainer who reported the bug, you can follow the thread [here](https://github.com/dotnet/aspnetcore/issues/68371){:target="blank" rel="noopener"}, he acknowledge the information then I was free to start implementing it.


## Bug summary

Quick summary about the issue, on Kestrel HTTP implementation there were a small bug when the server received newline chars characters `\n\r`, this was supposed to refuse such for [trailers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Trailer){:target="blank" rel="noopener"} and in HPACK Dynamic table retrieval, since both was not happening properly this was not in compliance with [RFC 7540 10.3](https://www.rfc-editor.org/rfc/rfc7540.html#section-10.3){:target="blank" rel="noopener"}.

The bug fix was kinda trivial, I just had to flip over a flag because the actual validation was present in code already, but one of the maintainers suggestions was writing tests to lock down the behavior and here is where made me go into the bones to dissect some parts of the HTTP protocol and HPACK, later we will explore each test and the concepts behind.

The bug was fixed in two places: 

`HttpProtocol.cs` more specific `OnTrailers`

```diff 
    string key = name.GetHeaderName();
-   var valueStr = value.GetRequestHeaderString(key, HttpRequestHeaders.EncodingSelector, checkForNewlineChars: false);
+   var valueStr = value.GetRequestHeaderString(key, HttpRequestHeaders.EncodingSelector, checkForNewlineChars: true);
    RequestTrailers.Append(key, valueStr);
     
```
`Http2Connection.cs` more specific `OnHeaderCore`

```diff
{
    UpdateHeaderParsingState(value, GetPseudoHeaderField(name));

-   _currentHeadersStream.OnHeader(name, value, checkForNewlineChars: false);
+   _currentHeadersStream.OnHeader(name, value, checkForNewlineChars: true);
}

```



