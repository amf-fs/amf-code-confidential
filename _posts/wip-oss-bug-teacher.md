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

The bug fix was kinda trivial, I just had to flip over a flag because the actual validation was present in code already, but one of the maintainers suggestions was writing tests to lockdown the behavior and here is where made me go into the bones to dissect some parts of the HTTP protocol and HPACK, later we will explore each test and the concepts behind.

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

## Testing trailers

For me a new contributor to the framework, writing the tests was an extremely valuable effort, first let's dig into how we make sure, when newline characters as CR LF are sent into trailers the HTTP Connection is refusing it. For my luck there is already a written test for this scenario I just need to extend it.

*Http2ConnectionTests.cs*
```csharp
[Theory]
[MemberData(nameof(IllegalTrailerData))]
public async Task HEADERS_Received_WithTrailers_ContainsIllegalTrailer_ConnectionError(byte[] trailers, string expectedErrorMessage)
{
    await InitializeConnectionAsync(_readTrailersApplication);

    await SendHeadersAsync(1, Http2HeadersFrameFlags.END_HEADERS, _browserRequestHeaders);
    await SendHeadersAsync(1, Http2HeadersFrameFlags.END_HEADERS | Http2HeadersFrameFlags.END_STREAM, trailers);

    await WaitForConnectionErrorAsync<Http2ConnectionErrorException>(
        ignoreNonGoAwayFrames: false,
        expectedLastStreamId: 1,
        expectedErrorCode: Http2ErrorCode.PROTOCOL_ERROR,
        expectedErrorMessage: expectedErrorMessage);

    AssertConnectionEndReason(ConnectionEndReason.InvalidRequestHeaders);
}
```
There is already a test data called IllegalTrailerData, I just added my two new scenarios before patching the fix and waited for each to fail so I make sure the test is covering what I need.

```diff
+   //Invalid header CR - contains-cr: \r
+   {
+       new byte[]{0x00, 0x0B}.Concat(Encoding.ASCII.GetBytes("contains-cr")).Concat(new byte[]{0x01, 0x0D}).ToArray(),
+       CoreStrings.BadRequest_MalformedRequestInvalidHeaders
+   },
+   //Invalid header LF - contains-lf: \n
+   {
+       new byte[]{0x00, 0x0B}.Concat(Encoding.ASCII.GetBytes("contains-lf")).Concat(new byte[]{0x01, 0x0A}).ToArray(),
+       CoreStrings.BadRequest_MalformedRequestInvalidHeaders
+   },
+   //Invalid header CR and LF - contains-crlf: \r\n
+   {
+       new byte[]{0x00, 0x0D}.Concat(Encoding.ASCII.GetBytes("contains-crlf")).Concat(new byte[]{0x02, 0x0D, 0x0A}).ToArray(),
+       CoreStrings.BadRequest_MalformedRequestInvalidHeaders
+   }
```
The test body itself is quite simple and the test api available makes easy to understand without gigging to much in details, short explanation it initialize a new HttpConnection for that you need an application, which pretty much are pre defined and tailored on base class to attend various scenarios, the app is anything that can process a Http request. Having a connection you can use pre built apis to send headers and data, in case we need trailer it needs to signalize this will end the stream along with trailers, then we just wait for the error to be returned, remember this is a web server so request are processed async in a loop, so you need that wait time.

Now the fun part pay attention to the test data how I end up with those bytes? Here is where HPACK start to play and I had to go deeper to understand the basic of this encoding.

## HPACk
